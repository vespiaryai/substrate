// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package steps

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
)

func testS3CAPEM(t *testing.T) []byte {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}

func testS3CAFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestK3sS3CAInputAndEarlyFailure(t *testing.T) {
	valid := testS3CAPEM(t)
	cert, err := x509.ParseCertificate(pemBlock(t, valid).Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		data    []byte
		missing bool
	}{
		{"empty", nil, false},
		{name: "missing", missing: true},
		{"junk", append(append([]byte{}, valid...), []byte("junk")...), false},
		{"leading junk", append([]byte("junk"), valid...), false},
		{"private key", []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"), false},
		{"malformed certificate", []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), false},
		{"mixed key", append(append([]byte{}, valid...), []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := testS3CAFile(t, tc.data)
			if tc.missing {
				path = filepath.Join(t.TempDir(), "missing.pem")
			}
			for _, deploy := range []struct {
				name string
				run  func(*Env) error
			}{
				{"full", func(e *Env) error { return e.DeployAteSystem(context.Background(), DeployOptions{SetupCSI: "none"}) }},
				{"api", func(e *Env) error { return e.DeployAteAPIServer(context.Background()) }},
				{"atelet", func(e *Env) error { return e.DeployAtelet(context.Background()) }},
			} {
				t.Run(deploy.name, func(t *testing.T) {
					client := fake.NewSimpleClientset()
					cfg := k3sTestConfig()
					cfg.K3s.S3CAFile = path
					e := &Env{Cfg: cfg, Kube: &kube.Client{Typed: client}}
					if err := deploy.run(e); err == nil || strings.Contains(err.Error(), string(tc.data)) && len(tc.data) > 0 {
						t.Fatalf("unsafe input error = %v", err)
					}
					if got := len(client.Actions()); got != 0 {
						t.Fatalf("API actions = %d, want zero", got)
					}
				})
			}
		})
	}
	if !validS3CAPEM(valid, time.Now()) || validS3CAPEM(valid, cert.NotAfter.Add(time.Second)) || validS3CAPEM(valid, cert.NotBefore.Add(-time.Second)) {
		t.Fatal("certificate validity bounds ignored")
	}
}

func pemBlock(t *testing.T, data []byte) *pem.Block {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("missing test certificate")
	}
	return block
}

func TestK3sS3CAConfigMapOwnershipAndRotation(t *testing.T) {
	client := fake.NewSimpleClientset()
	e := &Env{Cfg: k3sTestConfig(), Kube: &kube.Client{Typed: client}}
	e.Cfg.K3s.S3CAFile = testS3CAFile(t, testS3CAPEM(t))
	if err := e.prepareK3sS3CA(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.reconcileK3sS3CA(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := len(client.Actions()); got != 2 {
		t.Fatalf("initial actions = %d, want get/create", got)
	}
	if err := e.reconcileK3sS3CA(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := len(client.Actions()); got != 3 {
		t.Fatalf("repeat actions = %d, want read only", got)
	}
	e.s3CA = &s3CAPlan{pem: append(append([]byte{}, e.s3CA.pem...), '\n'), hash: "changed"}
	if err := e.reconcileK3sS3CA(ctx, false); err == nil {
		t.Fatal("standalone rotation accepted")
	}
	if got := len(client.Actions()); got != 4 {
		t.Fatalf("standalone rotation actions = %d, want read only", got)
	}
	if err := e.reconcileK3sS3CA(ctx, true); err != nil {
		t.Fatal(err)
	}
	cm, err := client.CoreV1().ConfigMaps(NamespaceAteSystem).Get(ctx, s3CAConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cm.BinaryData[s3CAKey], e.s3CA.pem) {
		t.Fatal("updated bundle differs from the input snapshot")
	}
	cm.Labels[s3CAOwnerKey] = "foreign"
	if _, err := client.CoreV1().ConfigMaps(NamespaceAteSystem).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.reconcileK3sS3CA(ctx, true); err == nil {
		t.Fatal("foreign ConfigMap adopted")
	}
}

func TestK3sS3CAUpdateConflictPreservesObject(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: s3CAConfigMap, Namespace: NamespaceAteSystem, ResourceVersion: "17", Labels: map[string]string{s3CAOwnerKey: s3CAOwner}},
		BinaryData: map[string][]byte{s3CAKey: []byte("old")},
	})
	client.PrependReactor("update", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, s3CAConfigMap, errors.New("changed concurrently"))
	})
	e := &Env{Cfg: k3sTestConfig(), Kube: &kube.Client{Typed: client}, s3CA: &s3CAPlan{pem: []byte("new")}}
	if err := e.reconcileK3sS3CA(context.Background(), true); !apierrors.IsConflict(err) {
		t.Fatalf("update error = %v, want conflict", err)
	}
	cm, err := client.CoreV1().ConfigMaps(NamespaceAteSystem).Get(context.Background(), s3CAConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(cm.BinaryData[s3CAKey]) != "old" {
		t.Fatal("object changed after conflict")
	}
}

func TestK3sS3CAProjectionAndSDKRequest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Errorf("unsigned S3 request")
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte("<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>"))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	e := &Env{Cfg: k3sTestConfig()}
	e.Cfg.K3s.S3Endpoint = server.URL
	e.Cfg.K3s.S3CAFile = testS3CAFile(t, ca)
	if err := e.prepareK3sS3CA(); err != nil {
		t.Fatal(err)
	}
	manifest, err := e.Kustomize("manifests/ate-install/k3s")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = e.configureK3sManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.configureK3sManifest(manifest)
	if err != nil || !bytes.Equal(manifest, again) {
		t.Fatalf("repeat render differs: %v", err)
	}
	objects, err := kube.DecodeManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, obj := range objects {
		containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		for _, raw := range containers {
			container := raw.(map[string]interface{})
			name, _ := container["name"].(string)
			if name != "ate-api-server" && name != "atelet" {
				continue
			}
			found[name] = true
			assertS3CAProjection(t, obj, container, e.s3CA.hash)
			bundlePath := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(bundlePath, ca, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, raw := range container["env"].([]interface{}) {
				entry := raw.(map[string]interface{})
				name, _ := entry["name"].(string)
				if name == "AWS_ENDPOINT_URL" || name == "AWS_REGION" || name == "AWS_S3_USE_PATH_STYLE" {
					t.Setenv(name, entry["value"].(string))
				}
			}
			t.Setenv("AWS_CA_BUNDLE", bundlePath)
			t.Setenv("AWS_ACCESS_KEY_ID", "test")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			cfg, err := awsconfig.LoadDefaultConfig(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = os.Getenv("AWS_S3_USE_PATH_STYLE") == "true" })
			if _, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{}); err != nil {
				t.Fatalf("%s signed TLS request: %v", name, err)
			}
			t.Setenv("AWS_CA_BUNDLE", "")
			cfg, err = awsconfig.LoadDefaultConfig(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			client = s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = os.Getenv("AWS_S3_USE_PATH_STYLE") == "true" })
			if _, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{}); err == nil {
				t.Fatalf("%s trusted private endpoint without bundle", name)
			}
		}
	}
	if !found["ate-api-server"] || !found["atelet"] || requests != 2 {
		t.Fatalf("targets = %v, successful requests = %d", found, requests)
	}
}

func TestK3sS3CAProjectionRejectsReservedCollisions(t *testing.T) {
	ca := &s3CAPlan{hash: "expected"}
	for _, tc := range []struct {
		name string
		edit func(*unstructured.Unstructured, map[string]interface{})
	}{
		{"volume", func(obj *unstructured.Unstructured, _ map[string]interface{}) {
			_ = unstructured.SetNestedSlice(obj.Object, []interface{}{map[string]interface{}{"name": s3CAVolume, "secret": map[string]interface{}{"secretName": "foreign"}}}, "spec", "template", "spec", "volumes")
		}},
		{"mount", func(_ *unstructured.Unstructured, c map[string]interface{}) {
			c["volumeMounts"] = []interface{}{map[string]interface{}{"name": s3CAVolume, "mountPath": "/other"}}
		}},
		{"environment", func(_ *unstructured.Unstructured, c map[string]interface{}) {
			c["env"] = []interface{}{map[string]interface{}{"name": "AWS_CA_BUNDLE", "value": "/other"}}
		}},
		{"annotation", func(obj *unstructured.Unstructured, _ map[string]interface{}) {
			_ = unstructured.SetNestedStringMap(obj.Object, map[string]string{s3CAHashKey: "foreign"}, "spec", "template", "metadata", "annotations")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: map[string]interface{}{"spec": map[string]interface{}{"template": map[string]interface{}{"spec": map[string]interface{}{}}}}}
			container := map[string]interface{}{"name": "ate-api-server"}
			tc.edit(obj, container)
			if err := addK3sS3CAProjection(obj, container, ca); err == nil {
				t.Fatal("reserved collision accepted")
			}
		})
	}
}

func TestK3sS3CAStandaloneManifests(t *testing.T) {
	e := &Env{Cfg: k3sTestConfig(), s3CA: &s3CAPlan{hash: "test-hash"}}
	api, err := os.ReadFile(e.Cfg.Manifest("ate-api-server.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	atelet, err := e.Kustomize("manifests/ate-install/k3s/atelet")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, target string
		manifest     []byte
	}{
		{"api", "ate-api-server", api},
		{"atelet", "atelet", atelet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := e.configureK3sManifest(tc.manifest)
			if err != nil {
				t.Fatal(err)
			}
			objects, err := kube.DecodeManifestBytes(result)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, obj := range objects {
				containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
				for _, raw := range containers {
					container := raw.(map[string]interface{})
					if container["name"] == tc.target {
						assertS3CAProjection(t, obj, container, e.s3CA.hash)
						found = true
					}
				}
			}
			if !found {
				t.Fatal("target pod not rendered")
			}
		})
	}
}

func TestK3sS3CAUnsetLeavesPodsWithoutBundle(t *testing.T) {
	e := &Env{Cfg: k3sTestConfig()}
	manifest, err := e.Kustomize("manifests/ate-install/k3s")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = e.configureK3sManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := kube.DecodeManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range objects {
		containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		for _, raw := range containers {
			container := raw.(map[string]interface{})
			if !isK3sS3CATarget(obj, container) {
				continue
			}
			env, _ := container["env"].([]interface{})
			mounts, _ := container["volumeMounts"].([]interface{})
			volumes, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "volumes")
			annotations, _, _ := unstructured.NestedStringMap(obj.Object, "spec", "template", "metadata", "annotations")
			if countNamed(env, "AWS_CA_BUNDLE") != 0 || countNamed(mounts, s3CAVolume) != 0 || countNamed(volumes, s3CAVolume) != 0 || annotations[s3CAHashKey] != "" {
				t.Fatalf("%s gained CA projection without input", obj.GetName())
			}
		}
	}
}

func assertS3CAProjection(t *testing.T, obj *unstructured.Unstructured, container map[string]interface{}, hash string) {
	t.Helper()
	annotations, _, _ := unstructured.NestedStringMap(obj.Object, "spec", "template", "metadata", "annotations")
	if annotations[s3CAHashKey] != hash {
		t.Fatalf("%s hash = %q", obj.GetName(), annotations[s3CAHashKey])
	}
	volumes, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "volumes")
	if countNamed(volumes, s3CAVolume) != 1 {
		t.Fatalf("%s CA volumes = %d", obj.GetName(), countNamed(volumes, s3CAVolume))
	}
	mounts, _ := container["volumeMounts"].([]interface{})
	if countNamed(mounts, s3CAVolume) != 1 {
		t.Fatalf("%s CA mounts = %d", obj.GetName(), countNamed(mounts, s3CAVolume))
	}
	for _, raw := range mounts {
		mount := raw.(map[string]interface{})
		if mount["name"] == s3CAVolume && (mount["mountPath"] != "/run/ate-s3-ca" || mount["readOnly"] != true) {
			t.Fatalf("%s CA mount = %v", obj.GetName(), mount)
		}
	}
	env, _ := container["env"].([]interface{})
	if countNamed(env, "AWS_CA_BUNDLE") != 1 {
		t.Fatalf("%s AWS_CA_BUNDLE entries = %d", obj.GetName(), countNamed(env, "AWS_CA_BUNDLE"))
	}
	for _, raw := range env {
		entry := raw.(map[string]interface{})
		if entry["name"] == "AWS_CA_BUNDLE" && entry["value"] != s3CAPath {
			t.Fatalf("AWS_CA_BUNDLE = %v", entry)
		}
	}
}

func countNamed(items []interface{}, name string) int {
	count := 0
	for _, raw := range items {
		if raw.(map[string]interface{})["name"] == name {
			count++
		}
	}
	return count
}
