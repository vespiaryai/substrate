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

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
)

func TestCertificateCommandsKeepRuntimeIdentityAndAPIChecks(t *testing.T) {
	for _, command := range [][]string{{"create", "podcertificate-controller-cas"}, {"deploy", "podcertificate-controller"}, {"deploy", "podcert"}} {
		for _, tc := range []struct {
			name      string
			change    func(*corev1.NodeList)
			systemUID string
			resource  string
			want      string
		}{
			{name: "cluster UID", systemUID: "other", want: "kube-system UID does not match the approved k3s cluster"},
			{name: "no nodes", change: func(n *corev1.NodeList) { n.Items = nil }, want: "k3s profile requires exactly one node"},
			{name: "two nodes", change: func(n *corev1.NodeList) { n.Items = append(n.Items, n.Items[0]) }, want: "k3s profile requires exactly one node"},
			{name: "node name", change: func(n *corev1.NodeList) { n.Items[0].Name = "other" }, want: "k3s node identity does not match"},
			{name: "node UID", change: func(n *corev1.NodeList) { n.Items[0].UID = "other" }, want: "k3s node identity does not match"},
			{name: "OS", change: func(n *corev1.NodeList) { n.Items[0].Status.NodeInfo.OperatingSystem = "windows" }, want: "k3s requires a Linux node with the k3s kubelet and containerd"},
			{name: "runtime", change: func(n *corev1.NodeList) { n.Items[0].Status.NodeInfo.ContainerRuntimeVersion = "docker://1" }, want: "k3s requires a Linux node with the k3s kubelet and containerd"},
			{name: "kubelet", change: func(n *corev1.NodeList) { n.Items[0].Status.NodeInfo.KubeletVersion = "v1.36.5" }, want: "k3s requires a Linux node with the k3s kubelet and containerd"},
			{name: "Ready", change: func(n *corev1.NodeList) { n.Items[0].Status.Conditions[0].Status = corev1.ConditionFalse }, want: "k3s node must be Ready and schedulable"},
			{name: "unschedulable", change: func(n *corev1.NodeList) { n.Items[0].Spec.Unschedulable = true }, want: "k3s node must be Ready and schedulable"},
			{name: "NoSchedule", change: func(n *corev1.NodeList) {
				n.Items[0].Spec.Taints = []corev1.Taint{{Key: "blocked", Effect: corev1.TaintEffectNoSchedule}}
			}, want: "k3s single-node profile does not tolerate node scheduling taints"},
			{name: "NoExecute", change: func(n *corev1.NodeList) {
				n.Items[0].Spec.Taints = []corev1.Taint{{Key: "blocked", Effect: corev1.TaintEffectNoExecute}}
			}, want: "k3s single-node profile does not tolerate node scheduling taints"},
			{name: "missing PCR", resource: "podcertificaterequests", want: "k3s requires enabled API certificates.k8s.io/v1beta1/podcertificaterequests"},
			{name: "missing CTB", resource: "clustertrustbundles", want: "k3s requires enabled API certificates.k8s.io/v1beta1/clustertrustbundles"},
		} {
			t.Run(strings.Join(command, " ")+"/"+tc.name, func(t *testing.T) {
				isolateCertificateRoot(t)
				nodes := corev1.NodeList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "NodeList"}, Items: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-uid")}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux", KubeletVersion: "v1.36.5+k3s1", ContainerRuntimeVersion: "containerd://2.3.4"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}}}
				if tc.change != nil {
					tc.change(&nodes)
				}
				raw, err := json.Marshal(nodes)
				if err != nil {
					t.Fatal(err)
				}
				api := &certificateAPI{responses: map[string]string{"/api/v1/nodes": string(raw)}}
				if tc.systemUID != "" {
					api.responses["/api/v1/namespaces/kube-system"] = `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"other"}}`
				}
				if tc.resource != "" {
					resources := []metav1.APIResource{}
					for _, name := range []string{"podcertificaterequests", "clustertrustbundles"} {
						if name != tc.resource {
							resources = append(resources, metav1.APIResource{Name: name})
						}
					}
					raw, err := json.Marshal(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: "certificates.k8s.io/v1beta1", APIResources: resources})
					if err != nil {
						t.Fatal(err)
					}
					api.responses["/apis/certificates.k8s.io/v1beta1"] = string(raw)
				}
				server := httptest.NewServer(api)
				defer server.Close()
				leaf, _, err := rootCmd.Find(command)
				if err != nil {
					t.Fatal(err)
				}
				leaf.RunE = func(*cobra.Command, []string) error { return errors.New("unexpected certificate leaf") }
				rootCmd.SetArgs(certificateRootArgs(t, server.URL, command))
				if err := rootCmd.Execute(); err == nil || err.Error() != tc.want {
					t.Fatalf("error=%v, want %q", err, tc.want)
				}
				requests := api.observed()
				if len(requests) == 0 {
					t.Fatal("runtime failure occurred before any identity request")
				}
				for _, request := range requests {
					if !strings.HasPrefix(request, "GET ") || strings.Contains(request, "persistentvolume") {
						t.Errorf("unexpected request %s", request)
					}
				}
			})
		}
	}
}

func operationalSpellings(command *cobra.Command, prefix []string) [][]string {
	var paths [][]string
	if command.Runnable() && command != rootCmd && command.Name() != "help" {
		paths = append(paths, append([]string(nil), prefix...))
	}
	for _, child := range command.Commands() {
		for _, name := range append([]string{child.Name()}, child.Aliases...) {
			paths = append(paths, operationalSpellings(child, append(append([]string(nil), prefix...), name))...)
		}
	}
	return paths
}

func TestEveryOperationalLeafDefaultsStrict(t *testing.T) {
	future := &cobra.Command{Use: "future-install", RunE: func(*cobra.Command, []string) error { return nil }}
	nested := &cobra.Command{Use: "nested"}
	lookalike := &cobra.Command{Use: "podcertificate-controller", RunE: func(*cobra.Command, []string) error { return nil }}
	rootCmd.AddCommand(future)
	deployCmd.AddCommand(nested)
	nested.AddCommand(lookalike)
	t.Cleanup(func() { rootCmd.RemoveCommand(future); deployCmd.RemoveCommand(nested) })
	paths := operationalSpellings(rootCmd, nil)
	for _, path := range paths {
		leaf, _, err := rootCmd.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		certificate := leaf == deployPodCertControllerCmd || (leaf.Parent() == createCmd && leaf.Name() == "podcertificate-controller-cas")
		for _, missing := range []string{"endpoint", "region", "Secret", "bucket", "HTTP", "malformed URL", "missing host", "userinfo", "query", "fragment", "invalid Secret", "valid"} {
			t.Run(strings.Join(path, " ")+"/"+missing, func(t *testing.T) {
				isolateCertificateRoot(t)
				api := &certificateAPI{}
				server := httptest.NewServer(api)
				defer server.Close()
				sentinel := errors.New("operational leaf reached")
				leaf.RunE = func(*cobra.Command, []string) error { return sentinel }
				args := certificateRootArgs(t, server.URL, path)
				if leaf == deployAteSystemCmd {
					args = append(args, "--setup-csi=none")
				}
				if leaf == setupCSICmd {
					args = append(args, "none")
				}
				for _, setting := range []struct{ name, flag, value string }{{"endpoint", "k3s-s3-endpoint", "https://s3.example.test"}, {"region", "k3s-s3-region", "test"}, {"Secret", "k3s-s3-secret", "credentials"}, {"bucket", "storage-bucket-name", "snapshots"}} {
					if setting.name != missing {
						args = append(args, "--"+setting.flag+"="+setting.value)
					}
				}
				invalidEndpoints := map[string]string{"HTTP": "http://s3.example.test", "malformed URL": "://broken", "missing host": "https:///bucket", "userinfo": "https://user@s3.example.test", "query": "https://s3.example.test?key=value", "fragment": "https://s3.example.test#fragment"}
				if endpoint, ok := invalidEndpoints[missing]; ok {
					args = append(args, "--k3s-s3-endpoint="+endpoint)
				}
				if missing == "invalid Secret" {
					args = append(args, "--k3s-s3-secret=Invalid_Secret")
				}
				rootCmd.SetArgs(args)
				err := rootCmd.Execute()
				if certificate || missing == "valid" {
					if !errors.Is(err, sentinel) {
						t.Fatalf("certificate error=%v, want sentinel", err)
					}
					if len(api.observed()) != 3 {
						t.Fatalf("certificate requests=%v", api.observed())
					}
				} else {
					want := missingNativeS3
					if missing == "invalid Secret" {
						want = "invalid k3s S3 Secret name"
					}
					if err == nil || err.Error() != want {
						t.Fatalf("strict error=%v, want exact %q", err, want)
					}
					if len(api.observed()) != 0 {
						t.Fatalf("strict requests=%v", api.observed())
					}
				}
			})
		}
	}
}

func TestValidationPurposeRejectsNonOperationalIdentity(t *testing.T) {
	foreign := &cobra.Command{Use: "other"}
	deploy := &cobra.Command{Use: "deploy"}
	leaf := &cobra.Command{Use: "podcertificate-controller", RunE: func(*cobra.Command, []string) error { return nil }}
	foreign.AddCommand(deploy)
	deploy.AddCommand(leaf)
	for _, command := range []*cobra.Command{nil, rootCmd, createCmd, deployCmd, foreign, leaf, &cobra.Command{Use: "podcertificate-controller", RunE: func(*cobra.Command, []string) error { return nil }}} {
		if purpose := validationPurpose(command); purpose != config.ValidationStrict {
			t.Errorf("command %v purpose=%v", command, purpose)
		}
	}
}

func TestCertificateRecordReplaysWithoutAuthority(t *testing.T) {
	for _, command := range [][]string{{"deploy", "apiserver"}, {"deploy", "atelet"}, {"deploy", "ate-system"}} {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			isolateCertificateRoot(t)
			api := &certificateAPI{}
			server := httptest.NewServer(api)
			defer server.Close()
			certificate := []string{"create", "podcertificate-controller-cas"}
			leaf, _, err := rootCmd.Find(certificate)
			if err != nil {
				t.Fatal(err)
			}
			var record string
			sentinel := errors.New("record captured")
			leaf.RunE = func(*cobra.Command, []string) error {
				var err error
				record, _, err = config.RecordSuccess(t.TempDir(), "fixture", "", resolved)
				if err != nil {
					return err
				}
				return sentinel
			}
			rootCmd.SetArgs(certificateRootArgs(t, server.URL, certificate))
			if err := rootCmd.Execute(); !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			var report bytes.Buffer
			resolved.Report(&report, config.ReportOptions{})
			for _, forbidden := range []string{"validationPurpose", "ValidationCertificateBootstrap", "commandPath"} {
				if bytes.Contains(raw, []byte(forbidden)) || strings.Contains(report.String(), forbidden) {
					t.Fatalf("authority in record/report: %s", forbidden)
				}
			}
			for _, metadata := range []bool{false, true} {
				t.Run(map[bool]string{false: "original", true: "forged metadata"}[metadata], func(t *testing.T) {
					isolateCertificateRoot(t)
					if metadata {
						text := strings.Replace(string(raw), "cluster:\n", "cluster:\n  validationPurpose: certificate-bootstrap\n  commandPath: create podcertificate-controller-cas\n", 1)
						if text == string(raw) {
							t.Fatal("record has no cluster metadata")
						}
						if err := os.WriteFile(record, []byte(text), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					target, _, err := rootCmd.Find(command)
					if err != nil {
						t.Fatal(err)
					}
					target.RunE = func(*cobra.Command, []string) error { return errors.New("unexpected replay leaf") }
					args := append(append([]string(nil), command...), "--config="+record, "--no-dev-env")
					if target == deployAteSystemCmd {
						args = append(args, "--setup-csi=none")
					}
					rootCmd.SetArgs(args)
					before := len(api.observed())
					if err := rootCmd.Execute(); err == nil || err.Error() != missingNativeS3 {
						t.Fatalf("replay error=%v", err)
					}
					if len(api.observed()) != before {
						t.Fatal("strict replay contacted API")
					}
				})
			}
		})
	}
}

func TestUserChannelsCannotSelectValidationPurpose(t *testing.T) {
	for _, key := range []string{"validationPurpose", "commandPath", "skipStorage"} {
		t.Run("file/"+key, func(t *testing.T) {
			isolateCertificateRoot(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			body := "apiVersion: " + config.FileAPIVersion + "\nkind: " + config.FileKind + "\n" + key + ": certificate-bootstrap\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := config.ParseFile(path); err == nil || !strings.Contains(err.Error(), "unknown") {
				t.Fatalf("unknown key error=%v", err)
			}
		})
	}
	for _, flag := range []string{"--validation-purpose=certificate-bootstrap", "--command-path=create podcertificate-controller-cas", "--skip-storage"} {
		t.Run("flag/"+flag, func(t *testing.T) {
			isolateCertificateRoot(t)
			rootCmd.SetArgs([]string{"deploy", "apiserver", flag})
			if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
				t.Fatalf("unknown flag error=%v", err)
			}
		})
	}
	t.Run("environment", func(t *testing.T) {
		isolateCertificateRoot(t)
		for _, name := range []string{"ATE_VALIDATION_PURPOSE", "ATE_COMMAND_PATH", "ATE_SKIP_STORAGE"} {
			t.Setenv(name, "certificate-bootstrap")
		}
		api := &certificateAPI{}
		server := httptest.NewServer(api)
		defer server.Close()
		rootCmd.SetArgs(certificateRootArgs(t, server.URL, []string{"deploy", "apiserver"}))
		if err := rootCmd.Execute(); err == nil || err.Error() != missingNativeS3 {
			t.Fatalf("environment error=%v", err)
		}
		if len(api.observed()) != 0 {
			t.Fatal("fake authority reached API")
		}
	})
	t.Run("generic type parse", func(t *testing.T) {
		isolateCertificateRoot(t)
		rootCmd.SetArgs([]string{"create", "podcertificate-controller-cas", "--no-dev-env", "--k3s=not-a-bool"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("generic parse error=%v", err)
		}
	})
}
