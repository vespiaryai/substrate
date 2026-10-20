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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/log"
)

const missingNativeS3 = "k3s requires an explicit HTTPS S3 endpoint, region, bucket and existing credential Secret"

func isolateCertificateRoot(t *testing.T) {
	t.Helper()
	oldEnv, oldResolved := env, resolved
	oldConfig, oldDev, oldReport := configPath, noDevEnv, noReportDefaults
	oldLog := log.Writer()
	t.Cleanup(func() {
		env, resolved = oldEnv, oldResolved
		configPath, noDevEnv, noReportDefaults = oldConfig, oldDev, oldReport
		log.SetOutput(oldLog)
	})
	env, resolved = nil, nil
	configPath, noDevEnv, noReportDefaults = "", false, false
	log.SetOutput(io.Discard)
	for _, setting := range config.All() {
		if setting.Env != "" {
			t.Setenv(setting.Env, "")
			if err := os.Unsetenv(setting.Env); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv(config.ConfigPathEnv, "")
	t.Setenv("NO_DEV_ENV", "1")
	seen := map[*pflag.Flag]bool{}
	var save func(*cobra.Command)
	save = func(command *cobra.Command) {
		original := *command
		t.Cleanup(func() { *command = original })
		for _, flags := range []*pflag.FlagSet{command.Flags(), command.PersistentFlags()} {
			flags.VisitAll(func(flag *pflag.Flag) {
				if seen[flag] {
					return
				}
				seen[flag] = true
				changed, value := flag.Changed, flag.Value.String()
				if slice, ok := flag.Value.(pflag.SliceValue); ok {
					values := append([]string(nil), slice.GetSlice()...)
					t.Cleanup(func() {
						if err := slice.Replace(values); err != nil {
							t.Errorf("restore --%s: %v", flag.Name, err)
						}
						flag.Changed = changed
					})
				} else {
					t.Cleanup(func() {
						if err := flag.Value.Set(value); err != nil {
							t.Errorf("restore --%s: %v", flag.Name, err)
						}
						flag.Changed = changed
					})
				}
				flag.Changed = false
			})
		}
		for _, child := range command.Commands() {
			save(child)
		}
	}
	save(rootCmd)
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
}

type certificateAPI struct {
	mu        sync.Mutex
	requests  []string
	responses map[string]string
}

func (api *certificateAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	api.mu.Lock()
	api.requests = append(api.requests, r.Method+" "+r.URL.Path)
	api.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"Forbidden","code":403}`, http.StatusForbidden)
		return
	}
	if body, ok := api.responses[r.URL.Path]; ok {
		_, _ = io.WriteString(w, body)
		return
	}
	switch r.URL.Path {
	case "/api/v1/namespaces/kube-system":
		_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"system-uid"}}`)
	case "/api/v1/nodes":
		_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"NodeList","items":[{"metadata":{"name":"node-a","uid":"node-uid"},"status":{"nodeInfo":{"operatingSystem":"linux","kubeletVersion":"v1.36.5+k3s1","containerRuntimeVersion":"containerd://2.3.4"},"conditions":[{"type":"Ready","status":"True"}]}}]}`)
	case "/apis/certificates.k8s.io/v1beta1":
		_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"APIResourceList","groupVersion":"certificates.k8s.io/v1beta1","resources":[{"name":"podcertificaterequests","kind":"PodCertificateRequest"},{"name":"clustertrustbundles","kind":"ClusterTrustBundle"}]}`)
	case "/api/v1/persistentvolumes":
		_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"PersistentVolumeList","items":[{"metadata":{"name":"retained-zot-pv"}}]}`)
	case "/api/v1/persistentvolumeclaims":
		_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"PersistentVolumeClaimList","items":[{"metadata":{"namespace":"zot","name":"retained-zot-pvc"}}]}`)
	default:
		http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, http.StatusNotFound)
	}
}

func (api *certificateAPI) observed() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.requests...)
}

func certificateRootArgs(t *testing.T, address string, command []string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n  cluster:\n    server: %s\ncontexts:\n- name: fixture\n  context:\n    cluster: fixture\n    user: fixture\ncurrent-context: fixture\nusers:\n- name: fixture\n  user: {}\n", address)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string(nil), command...)
	return append(args, "--no-dev-env", "--no-report-defaults", "--kind=false", "--k3s",
		"--kubeconfig="+path, "--context=fixture", "--k3s-node=node-a", "--k3s-node-uid=node-uid",
		"--k3s-system-uid=system-uid", "--k3s-kubelet-root=/var/lib/kubelet",
		"--cluster-size=size0", "--atenet-dataplane=envoy")
}

func TestCertificateCommandsReachLeafWithoutS3(t *testing.T) {
	for _, command := range [][]string{
		{"create", "podcertificate-controller-cas"},
		{"deploy", "podcertificate-controller"},
		{"deploy", "podcert"},
	} {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			isolateCertificateRoot(t)
			api := &certificateAPI{}
			server := httptest.NewServer(api)
			defer server.Close()
			leaf, _, err := rootCmd.Find(command)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("certificate leaf reached: " + strings.Join(command, " "))
			leaf.RunE = func(*cobra.Command, []string) error { return sentinel }
			rootCmd.SetArgs(certificateRootArgs(t, server.URL, command))
			err = rootCmd.Execute()
			requests := api.observed()
			t.Logf("root result = %v; HTTP requests = %v", err, requests)
			if !errors.Is(err, sentinel) {
				t.Errorf("root execution = %v, want %v", err, sentinel)
				if err == nil || err.Error() != missingNativeS3 {
					t.Errorf("baseline refusal = %v, want exact %q", err, missingNativeS3)
				}
				if len(requests) != 0 {
					t.Errorf("baseline requests = %v, want none", requests)
				}
				return
			}
			want := []string{"GET /api/v1/namespaces/kube-system", "GET /api/v1/nodes", "GET /apis/certificates.k8s.io/v1beta1"}
			if !reflect.DeepEqual(requests, want) {
				t.Errorf("certificate requests = %v, want %v", requests, want)
			}
		})
	}
}

func TestStorageCommandRejectsMissingS3BeforeRequests(t *testing.T) {
	isolateCertificateRoot(t)
	api := &certificateAPI{}
	server := httptest.NewServer(api)
	defer server.Close()
	leaf, _, err := rootCmd.Find([]string{"deploy", "apiserver"})
	if err != nil {
		t.Fatal(err)
	}
	leaf.RunE = func(*cobra.Command, []string) error { return errors.New("storage leaf reached") }
	rootCmd.SetArgs(certificateRootArgs(t, server.URL, []string{"deploy", "apiserver"}))
	err = rootCmd.Execute()
	t.Logf("root result = %v; HTTP requests = %v", err, api.observed())
	if err == nil || err.Error() != missingNativeS3 {
		t.Errorf("root execution = %v, want exact %q", err, missingNativeS3)
	}
	if requests := api.observed(); len(requests) != 0 {
		t.Errorf("requests = %v, want none", requests)
	}
}

func TestNativeRootFixtureReachesLeafWithS3(t *testing.T) {
	isolateCertificateRoot(t)
	api := &certificateAPI{}
	server := httptest.NewServer(api)
	defer server.Close()
	command := []string{"deploy", "podcertificate-controller"}
	leaf, _, err := rootCmd.Find(command)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("native fixture leaf reached")
	leaf.RunE = func(*cobra.Command, []string) error { return sentinel }
	args := certificateRootArgs(t, server.URL, command)
	args = append(args, "--k3s-s3-endpoint=https://s3.example.test", "--k3s-s3-region=test", "--k3s-s3-secret=snapshot-credentials", "--storage-bucket-name=snapshots")
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); !errors.Is(err, sentinel) {
		t.Errorf("root execution = %v, want %v", err, sentinel)
	}
	want := []string{"GET /api/v1/namespaces/kube-system", "GET /api/v1/nodes", "GET /apis/certificates.k8s.io/v1beta1"}
	if requests := api.observed(); !reflect.DeepEqual(requests, want) {
		t.Errorf("native fixture requests = %v, want %v", requests, want)
	}
}
