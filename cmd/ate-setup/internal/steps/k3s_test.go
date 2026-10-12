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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
)

func TestK3sMachineID(t *testing.T) {
	for _, tc := range []struct {
		name, local, node string
		wantError         bool
	}{
		{"matching", "abc123", "abc123", false},
		{"matching with newline", "abc123\n", "abc123", false},
		{"empty local", "", "abc123", true},
		{"blank local", "\n", "abc123", true},
		{"empty node", "abc123", "", true},
		{"both empty", "", "", true},
		{"different", "abc123", "def456", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateK3sMachineID(tc.local, tc.node)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error = %v", err, tc.wantError)
			}
		})
	}
}

func k3sTestConfig() *config.Config {
	return &config.Config{Root: filepath.Join("..", "..", "..", ".."), Kubeconfig: "/explicit/config", Context: "local", Router: config.RouterEnvoy, ClusterSize: config.ClusterSizeSize0, BucketName: "snapshots", K3s: &config.K3sProfile{Node: "fedora", NodeUID: "node-uid", SystemUID: "system-uid", KubeletRoot: "/custom/kubelet", S3Endpoint: "https://s3.example.test", S3Region: "test", S3Secret: "snapshot-credentials"}}
}

func TestK3sPreflightMissingAPIsDoesNotWrite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("preflight attempted %s %s", r.Method, r.URL.Path)
			http.Error(w, "no writes", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			_ = json.NewEncoder(w).Encode(corev1.Namespace{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("system-uid")}})
		case "/api/v1/nodes":
			_ = json.NewEncoder(w).Encode(corev1.NodeList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "NodeList"}, Items: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "fedora", UID: types.UID("node-uid")}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux", KubeletVersion: "v1.36.5+k3s1", ContainerRuntimeVersion: "containerd://2.3.4"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}}})
		default:
			http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`, 404)
		}
	}))
	defer server.Close()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{Cfg: k3sTestConfig(), Kube: &kube.Client{Typed: client}}
	if err := e.SetupCSI(context.Background(), "hostpath"); err == nil {
		t.Fatal("missing certificate APIs accepted")
	}
}

func TestK3sRenderUsesNativeHostPathsAndTLS(t *testing.T) {
	e := &Env{Cfg: k3sTestConfig()}
	objs, err := e.renderK3sHostpath()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	roleBindings := 0
	proxyTLS := false
	for _, obj := range objs {
		if obj.GetKind() == "RoleBinding" {
			roleBindings++
			if obj.GetNamespace() != "default" {
				t.Fatalf("RoleBinding %s namespace = %q", obj.GetName(), obj.GetNamespace())
			}
		}
		if obj.GetKind() == "Service" && obj.GetName() == "hostpath-service" {
			t.Fatal("unneeded external NodePort retained")
		}
		if obj.GetKind() == "ConfigMap" && obj.GetName() == "csi-hostpath-envoy-config" {
			value, _, _ := unstructured.NestedString(obj.Object, "data", "envoy.yaml")
			proxyTLS = strings.Contains(value, "require_client_certificate: true")
		}
		if obj.GetKind() != "StatefulSet" {
			continue
		}
		found++
		node, _, _ := unstructured.NestedString(obj.Object, "spec", "template", "spec", "nodeName")
		if node != "fedora" {
			t.Fatalf("nodeName = %q", node)
		}
		volumes, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "volumes")
		socket := false
		for _, v := range volumes {
			volume := v.(map[string]interface{})
			if volume["name"] == "socket-dir" {
				hp := volume["hostPath"].(map[string]interface{})
				if hp["path"] != "/custom/kubelet/plugins/csi-hostpath" {
					t.Fatalf("socket host path = %v", hp["path"])
				}
				socket = true
			}
		}
		if !socket {
			t.Fatal("missing socket volume")
		}
		if obj.GetName() == "csi-hostpathplugin" {
			containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
			registrar := false
			propagation := false
			nativeMounts := map[string]string{}
			for _, v := range containers {
				c := v.(map[string]interface{})
				if c["name"] == "node-driver-registrar" {
					for _, arg := range c["args"].([]interface{}) {
						if arg == "--kubelet-registration-path=/custom/kubelet/plugins/csi-hostpath/csi.sock" {
							registrar = true
						}
					}
				}
				if c["name"] == "hostpath" {
					for _, m := range c["volumeMounts"].([]interface{}) {
						mount := m.(map[string]interface{})
						nativeMounts[mount["name"].(string)] = mount["mountPath"].(string)
						if mount["name"] == "ateom-dir" && mount["mountPath"] == "/var/lib/ate" && mount["mountPropagation"] == "Bidirectional" {
							propagation = true
						}
					}
				}
			}
			if nativeMounts["mountpoint-dir"] != "/custom/kubelet/pods" || nativeMounts["plugins-dir"] != "/custom/kubelet/plugins" {
				t.Fatalf("native hostpath mount paths = %v", nativeMounts)
			}
			if !registrar || !propagation {
				t.Fatal("native registrar or atelet propagation missing")
			}
		}
	}
	if !proxyTLS {
		t.Fatal("controller mutual TLS missing")
	}
	if found != 2 {
		t.Fatalf("StatefulSets = %d", found)
	}
	if roleBindings != 10 {
		t.Fatalf("RoleBindings = %d, want 10", roleBindings)
	}

}

func TestK3sAteletRenderKeepsTLSAndUsesExistingSecret(t *testing.T) {
	e := &Env{Cfg: k3sTestConfig()}
	manifest, err := e.Kustomize("manifests/ate-install/k3s")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = e.configureK3sManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	objs, err := kube.DecodeManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	targets := 0
	for _, obj := range objs {
		containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		for _, v := range containers {
			c := v.(map[string]interface{})
			if c["name"] != "atelet" && c["name"] != "ate-api-server" {
				continue
			}
			targets++
			env := c["env"].([]interface{})
			names := map[string]bool{}
			for _, v := range env {
				pair := v.(map[string]interface{})
				name := pair["name"].(string)
				if names[name] {
					t.Fatalf("duplicate env %s", name)
				}
				names[name] = true
				if name == "ATE_STORAGE_BACKEND" && pair["value"] != "s3" {
					t.Fatal("GCS default retained")
				}
				if name == "AWS_ACCESS_KEY_ID" {
					ref := pair["valueFrom"].(map[string]interface{})["secretKeyRef"].(map[string]interface{})
					if ref["name"] != "snapshot-credentials" {
						t.Fatal("wrong credential Secret")
					}
				}
			}
			if c["name"] == "atelet" {
				args := c["args"].([]interface{})
				tls := false
				for _, arg := range args {
					if arg == "--grpc-server-cred-bundle=/run/podidentity.podcert.ate.dev/credential-bundle.pem" {
						tls = true
					}
					if arg == "--image-credential-provider-config=/run/image-credential-provider/config.yaml" {
						t.Fatal("cloud credential provider retained")
					}
				}
				if !tls {
					t.Fatal("TLS missing")
				}
				volumes, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "volumes")
				for _, v := range volumes {
					volume := v.(map[string]interface{})
					if volume["name"] == "kubelet-plugins" {
						if volume["hostPath"].(map[string]interface{})["path"] != "/custom/kubelet/plugins" {
							t.Fatal("wrong native plugins directory")
						}
					}
				}
			}
		}
	}
	if targets != 2 {
		t.Fatalf("configured targets = %d", targets)
	}
}

func TestK3sPostgresUsesSmallTLSOverlay(t *testing.T) {
	e := &Env{Cfg: k3sTestConfig()}
	manifest, err := e.render(e.postgresManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	objs, err := kube.DecodeManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, obj := range objs {
		if obj.GetKind() != "StatefulSet" || obj.GetName() != "postgres" {
			continue
		}
		found = true
		claims, _, _ := unstructured.NestedSlice(obj.Object, "spec", "volumeClaimTemplates")
		storage, _, _ := unstructured.NestedString(claims[0].(map[string]interface{}), "spec", "resources", "requests", "storage")
		if storage != "1Gi" {
			t.Fatalf("PVC storage = %q", storage)
		}
		containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		for _, v := range containers {
			c := v.(map[string]interface{})
			if c["name"] != "postgres" {
				continue
			}
			for _, want := range [][3]string{{"requests", "cpu", "250m"}, {"limits", "cpu", "2"}, {"requests", "memory", "1Gi"}, {"limits", "memory", "2Gi"}} {
				got, _, _ := unstructured.NestedString(c, "resources", want[0], want[1])
				if got != want[2] {
					t.Fatalf("postgres %s %s = %q, want %q", want[0], want[1], got, want[2])
				}
			}
		}
		volumes, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "volumes")
		data, _ := json.Marshal(volumes)
		if !strings.Contains(string(data), "podCertificate") || !strings.Contains(string(data), "clusterTrustBundle") {
			t.Fatal("PostgreSQL TLS projections missing")
		}
	}
	if !found {
		t.Fatal("PostgreSQL StatefulSet missing")
	}
}

func TestK3sCSICreateRejectsPreflightRace(t *testing.T) {
	kinds := map[string]string{"Service": "v1", "ServiceAccount": "v1", "ClusterRole": "rbac.authorization.k8s.io/v1", "ClusterRoleBinding": "rbac.authorization.k8s.io/v1", "Role": "rbac.authorization.k8s.io/v1", "RoleBinding": "rbac.authorization.k8s.io/v1", "CSIDriver": "storage.k8s.io/v1", "StatefulSet": "apps/v1", "ConfigMap": "v1", "VolumeSnapshotClass": "snapshot.storage.k8s.io/v1", "StorageClass": "storage.k8s.io/v1", "CSIDriverConfig": "ate.dev/v1alpha1"}
	for kind, version := range kinds {
		t.Run(kind, func(t *testing.T) {
			existing := `{"spec":{"owner":"other-installer"}}`
			posts := 0
			created := false
			paths := map[string]string{
				"Service":             "/api/v1/namespaces/default/services",
				"ServiceAccount":      "/api/v1/namespaces/default/serviceaccounts",
				"ClusterRole":         "/apis/rbac.authorization.k8s.io/v1/clusterroles",
				"ClusterRoleBinding":  "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
				"Role":                "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles",
				"RoleBinding":         "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings",
				"CSIDriver":           "/apis/storage.k8s.io/v1/csidrivers",
				"StatefulSet":         "/apis/apps/v1/namespaces/default/statefulsets",
				"ConfigMap":           "/api/v1/namespaces/default/configmaps",
				"VolumeSnapshotClass": "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses",
				"StorageClass":        "/apis/storage.k8s.io/v1/storageclasses",
				"CSIDriverConfig":     "/apis/ate.dev/v1alpha1/csidriverconfigs",
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantPath := paths[kind]
				if r.Method == http.MethodGet {
					wantPath += "/test"
				}
				if r.URL.Path != wantPath {
					t.Errorf("%s path = %q, want %q", r.Method, r.URL.Path, wantPath)
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodGet:
					if created {
						_, _ = w.Write([]byte(`{"apiVersion":"` + version + `","kind":"` + kind + `","metadata":{"name":"test"},"spec":{"owner":"other-installer"}}`))
						return
					}
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`))
				case http.MethodPost:
					posts++
					if !created {
						t.Error("CREATE before concurrent resource exists")
					}
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","reason":"AlreadyExists","code":409}`))
				default:
					existing = "modified"
					t.Errorf("unsafe request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer server.Close()
			client, err := dynamic.NewForConfig(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			e := &Env{Kube: &kube.Client{Dynamic: client}}
			obj := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": version, "kind": kind, "metadata": map[string]interface{}{"name": "test"}}}
			objs := []*unstructured.Unstructured{obj}
			if err := e.checkK3sCSIAbsent(context.Background(), objs); err != nil {
				t.Fatal(err)
			}
			created = true
			err = e.createK3sCSI(context.Background(), objs)
			if !apierrors.IsAlreadyExists(err) {
				t.Fatalf("create conflict = %v", err)
			}
			if posts != 1 || existing != `{"spec":{"owner":"other-installer"}}` {
				t.Fatalf("posts=%d existing=%s", posts, existing)
			}
			gvr, err := k3sCSIResource(obj)
			if err != nil {
				t.Fatal(err)
			}
			retained, err := client.Resource(gvr).Namespace(obj.GetNamespace()).Get(context.Background(), "test", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			owner, _, _ := unstructured.NestedString(retained.Object, "spec", "owner")
			if owner != "other-installer" {
				t.Fatalf("existing spec changed: %v", retained.Object)
			}

		})
	}
}

func TestK3sCSIRejectsExistingDriverConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/apis/ate.dev/v1alpha1/csidriverconfigs/hostpath.csi.k8s.io" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"ate.dev/v1alpha1","kind":"CSIDriverConfig","metadata":{"name":"hostpath.csi.k8s.io"},"spec":{"driverName":"other"}}`))
	}))
	defer server.Close()
	client, err := dynamic.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{Kube: &kube.Client{Dynamic: client}}
	objs, err := kube.DecodeManifestBytes([]byte(k3sCSIDriverConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.checkK3sCSIAbsent(context.Background(), objs); err == nil || !strings.Contains(err.Error(), "refusing existing CSIDriverConfig") {
		t.Fatalf("existing driver config accepted: %v", err)
	}
}

func TestK3sCSIResourcePreservesExplicitNamespace(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": map[string]interface{}{"name": "test", "namespace": "custom"}}}
	if _, err := k3sCSIResource(obj); err != nil {
		t.Fatal(err)
	}
	if obj.GetNamespace() != "custom" {
		t.Fatalf("namespace = %q, want custom", obj.GetNamespace())
	}
}
