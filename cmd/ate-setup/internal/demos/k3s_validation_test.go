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

package demos_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/pflag"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/demos"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/steps"
)

func TestSharedDemoDeploymentRevalidatesCertificateLoadedConfig(t *testing.T) {
	for _, setting := range config.All() {
		if setting.Env != "" {
			t.Setenv(setting.Env, "")
			if err := os.Unsetenv(setting.Env); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv(config.ConfigPathEnv, "")
	requests := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			discovery := map[string]string{
				"/api":                          `{"apiVersion":"v1","kind":"APIVersions","versions":["v1"]}`,
				"/apis":                         `{"apiVersion":"v1","kind":"APIGroupList","groups":[{"name":"apiextensions.k8s.io","versions":[{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}}]}`,
				"/api/v1":                       `{"apiVersion":"v1","kind":"APIResourceList","groupVersion":"v1","resources":[{"name":"namespaces","kind":"Namespace"}]}`,
				"/apis/apiextensions.k8s.io/v1": `{"apiVersion":"v1","kind":"APIResourceList","groupVersion":"apiextensions.k8s.io/v1","resources":[{"name":"customresourcedefinitions","kind":"CustomResourceDefinition"}]}`,
			}
			if body, ok := discovery[r.URL.Path]; ok {
				_, _ = fmt.Fprint(w, body)
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","message":"demo reached API","code":403}`)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: local\n  cluster:\n    server: %s\ncontexts:\n- name: local\n  context:\n    cluster: local\n    user: local\nusers:\n- name: local\n  user: {}\n", server.URL)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := pflag.NewFlagSet("certificate", pflag.ContinueOnError)
	config.BindFlags(flags)
	for key, value := range map[string]string{"k3s": "true", "kubeconfig": path, "context": "local", "k3s-node": "node-a", "k3s-node-uid": "node-uid", "k3s-system-uid": "system-uid", "k3s-kubelet-root": "/var/lib/kubelet", "cluster-size": "size0", "atenet-dataplane": "envoy"} {
		if err := flags.Set(key, value); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.LoadFlags(flags, config.LoadOptions{NoDevEnv: true}, config.ValidationCertificateBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.K3s == nil || cfg.K3s.S3Endpoint != "" || cfg.BucketName != "" {
		t.Fatal("fixture is not certificate-loaded without S3")
	}
	client, err := kube.New(path, "local")
	if err != nil {
		t.Fatal(err)
	}
	env := &steps.Env{Cfg: cfg, Kube: client}
	renders := 0
	demo := &demos.Substrate{DemoName: "validation", RenderValues: func(context.Context, *steps.Env) (map[string]string, error) { renders++; return nil, nil }}
	if err := demo.Deploy(context.Background(), env); err == nil || err.Error() != "k3s requires an explicit HTTPS S3 endpoint, region, bucket and existing credential Secret" {
		t.Fatalf("missing S3 error=%v", err)
	}
	if requests.Load() != 0 || renders != 0 {
		t.Fatalf("activity before guard: requests=%d renders=%d", requests.Load(), renders)
	}
	cfg.K3s.S3Endpoint = "https://s3.example.test"
	cfg.K3s.S3Region = "test"
	cfg.K3s.S3Secret = "credentials"
	cfg.BucketName = "snapshots"
	if err := demo.Deploy(context.Background(), env); err == nil || !strings.Contains(err.Error(), "demo reached API") {
		t.Fatalf("valid S3 error=%v", err)
	}
	if requests.Load() < 1 || renders != 0 {
		t.Fatalf("valid S3 activity: requests=%d renders=%d", requests.Load(), renders)
	}
}
