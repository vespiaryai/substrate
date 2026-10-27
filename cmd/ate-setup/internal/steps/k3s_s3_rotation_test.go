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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
)

func rotationFixture(t *testing.T) (*Env, S3RotationExpected, []byte, string) {
	t.Helper()
	oldCA := testS3CAPEM(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(8127), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true}, &x509.Certificate{SerialNumber: big.NewInt(8127), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true}, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	newCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle := append(append([]byte{}, oldCA...), newCA...)
	if !validS3CAPEM(newCA, time.Now()) || !validS3CAPEM(bytes.Replace(bundle, bytes.TrimSpace(oldCA), nil, 1), time.Now()) {
		t.Fatal("new root is invalid")
	}
	endpoint := "https://old.example.test:9000"
	makeTemplate := func(label string) corev1.PodTemplateSpec {
		return corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": label}, Annotations: map[string]string{s3CAHashKey: rotationHash(oldCA)}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: label, Env: []corev1.EnvVar{{Name: "AWS_ENDPOINT_URL", Value: endpoint}, {Name: "AWS_CA_BUNDLE", Value: s3CAPath}}}}}}
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: s3CAConfigMap, Namespace: NamespaceAteSystem, UID: "ca-uid", ResourceVersion: "10", Labels: map[string]string{s3CAOwnerKey: s3CAOwner}}, BinaryData: map[string][]byte{s3CAKey: oldCA}}
	api := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "ate-api-server", Namespace: NamespaceAteSystem, UID: "api-uid", ResourceVersion: "11"}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "ate-api-server"}}, Template: makeTemplate("ate-api-server")}, Status: appsv1.DeploymentStatus{UpdatedReplicas: 1, AvailableReplicas: 1}}
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "atelet-v1", Namespace: NamespaceAteSystem, UID: "ds-uid", ResourceVersion: "12", Labels: map[string]string{"app": "atelet"}}, Spec: appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "atelet"}}, Template: makeTemplate("atelet")}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 1, UpdatedNumberScheduled: 1, NumberAvailable: 1}}
	apiPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: NamespaceAteSystem, UID: "api-pod-old", Labels: map[string]string{"app": "ate-api-server"}}}
	dsPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "ds-pod", Namespace: NamespaceAteSystem, UID: "ds-pod-old", Labels: map[string]string{"app": "atelet"}}}
	client := fake.NewSimpleClientset(cm, api, ds, apiPod, dsPod)
	cfg := k3sTestConfig()
	cfg.Context = "rotation-test"
	cfg.K3s.S3Endpoint = endpoint
	e := &Env{Cfg: cfg, Kube: &kube.Client{Typed: client}}
	expected, err := e.InspectS3Rotation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return e, expected, bundle, filepath.Join(t.TempDir(), "rotation.json")
}

func TestS3TrustRotationRejectsChangedStateBeforeWrite(t *testing.T) {
	for _, change := range []string{"owner", "hash", "uid", "version", "template"} {
		t.Run(change, func(t *testing.T) {
			e, expected, bundle, path := rotationFixture(t)
			client := e.Kube.Typed
			switch change {
			case "owner":
				cm, _ := client.CoreV1().ConfigMaps(e.Namespace()).Get(context.Background(), s3CAConfigMap, metav1.GetOptions{})
				cm.Labels[s3CAOwnerKey] = "other"
				_, _ = client.CoreV1().ConfigMaps(e.Namespace()).Update(context.Background(), cm, metav1.UpdateOptions{})
			case "hash":
				expected.CASHA256 = strings.Repeat("0", 64)
			case "uid":
				expected.CAUID = "stale"
			case "version":
				expected.CAResourceVersion = "stale"
			case "template":
				expected.Clients[0].TemplateSHA256 = "stale"
			}
			_, err := e.RotateS3Trust(context.Background(), S3TrustRotation{Expected: expected, CAPEM: bundle, ReceiptPath: path})
			if err == nil {
				t.Fatal("changed state accepted")
			}
			for _, action := range client.(*fake.Clientset).Actions() {
				if action.GetVerb() == "update" && change != "owner" {
					t.Fatalf("rotation wrote on mismatch: %s", action)
				}
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("receipt created on mismatch: %v", err)
			}
		})
	}
}

func TestS3TrustRotationConflictAndPartialRecovery(t *testing.T) {
	e, expected, bundle, receiptPath := rotationFixture(t)
	client := e.Kube.Typed.(*fake.Clientset)
	historicalPath := filepath.Join(t.TempDir(), "install.yaml")
	historical := []byte("historical installer receipt\n")
	if err := os.WriteFile(historicalPath, historical, 0o600); err != nil {
		t.Fatal(err)
	}
	failed := false
	client.PrependReactor("update", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
		if !failed {
			failed = true
			return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "apps", Resource: "daemonsets"}, "atelet-v1", nil)
		}
		return false, nil, nil
	})
	req := S3TrustRotation{Expected: expected, CAPEM: bundle, ReceiptPath: receiptPath}
	if _, err := e.RotateS3Trust(context.Background(), req); !apierrors.IsConflict(err) {
		t.Fatalf("first rotation = %v, want conflict", err)
	}
	if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatalf("receipt after conflict: %v", err)
	}
	for _, pod := range []struct {
		name string
		uid  types.UID
	}{{"api-pod", "api-pod-new"}, {"ds-pod", "ds-pod-new"}} {
		obj, _ := client.CoreV1().Pods(e.Namespace()).Get(context.Background(), pod.name, metav1.GetOptions{})
		obj.UID = pod.uid
		obj.Annotations = map[string]string{s3CAHashKey: rotationHash(bundle)}
		obj.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		if _, err := client.CoreV1().Pods(e.Namespace()).Update(context.Background(), obj, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	receipt, err := e.RotateS3Trust(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Phase != "trust" || receipt.TargetCASHA256 != rotationHash(bundle) || len(receipt.Observed) != 2 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if _, err := e.RotateS3Trust(context.Background(), req); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("receipt overwrite = %v", err)
	}
	got, err := os.ReadFile(historicalPath)
	if err != nil || !bytes.Equal(got, historical) {
		t.Fatalf("historical receipt changed: %v", err)
	}
}
