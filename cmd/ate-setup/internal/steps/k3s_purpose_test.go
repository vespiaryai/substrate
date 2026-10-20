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
	"errors"
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
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/images"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
)

const missingStorageReferences = "k3s requires an explicit HTTPS S3 endpoint, region, bucket and existing credential Secret"

func loadCertificateConfig(t *testing.T) *config.Config {
	t.Helper()
	for _, setting := range config.All() {
		if setting.Env != "" {
			t.Setenv(setting.Env, "")
			if err := os.Unsetenv(setting.Env); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv(config.ConfigPathEnv, "")
	fs := pflag.NewFlagSet("certificate", pflag.ContinueOnError)
	config.BindFlags(fs)
	for flag, value := range map[string]string{"k3s": "true", "kubeconfig": "/explicit/config", "context": "local", "k3s-node": "node-a", "k3s-node-uid": "node-uid", "k3s-system-uid": "system-uid", "k3s-kubelet-root": "/var/lib/kubelet", "cluster-size": "size0", "atenet-dataplane": "envoy", "credential-provider": `{"enabled":false}`} {
		if err := fs.Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.LoadFlags(fs, config.LoadOptions{NoDevEnv: true}, config.ValidationCertificateBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.K3s == nil || cfg.K3s.S3Endpoint != "" || cfg.BucketName != "" {
		t.Fatalf("not an S3-free certificate-loaded Config: %+v", cfg)
	}
	return cfg
}

type refusedImageResolver struct{ calls int }

func (r *refusedImageResolver) ResolvePath(context.Context, string) ([]byte, error) {
	r.calls++
	return nil, errors.New("unexpected image resolution")
}
func (r *refusedImageResolver) ResolveBytes(context.Context, []byte) ([]byte, error) {
	r.calls++
	return nil, errors.New("unexpected image resolution")
}

func guardedNativeEnv(t *testing.T, cfg *config.Config, reached error) (*Env, *atomic.Int32, *refusedImageResolver) {
	t.Helper()
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
		_, _ = fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","message":%q,"code":403}`, reached.Error())
	}))
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: local\n  cluster:\n    server: %s\ncontexts:\n- name: local\n  context:\n    cluster: local\n    user: local\nusers:\n- name: local\n  user: {}\n", server.URL)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := kube.New(path, "local")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &refusedImageResolver{}
	return &Env{Cfg: cfg, Kube: client, resolver: resolver, substrateVersion: "v0.0.0-test"}, requests, resolver
}

func TestStorageEntrancesRevalidateCertificateLoadedConfig(t *testing.T) {
	for _, entry := range []struct {
		name string
		run  func(*Env) error
	}{
		{"system CSI none", func(e *Env) error { return e.DeployAteSystem(context.Background(), DeployOptions{SetupCSI: "none"}) }},
		{"apiserver", func(e *Env) error { return e.DeployAteAPIServer(context.Background()) }},
		{"atelet", func(e *Env) error { return e.DeployAtelet(context.Background()) }},
		{"API environment", func(e *Env) error { return e.CreateAPIServerEnvVars(context.Background()) }},
		{"CSI hostpath", func(e *Env) error { return e.SetupCSI(context.Background(), "hostpath") }},
		{"CSI preflight certificate purpose", func(e *Env) error {
			return e.PreflightK3s(context.Background(), true, config.ValidationCertificateBootstrap)
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			cfg := loadCertificateConfig(t)
			reached := errors.New("valid storage reached API")
			env, requests, resolver := guardedNativeEnv(t, cfg, reached)
			if err := entry.run(env); err == nil || err.Error() != missingStorageReferences {
				t.Fatalf("error=%v, want exact S3 refusal", err)
			}
			if requests.Load() != 0 || resolver.calls != 0 {
				t.Fatalf("activity before refusal: requests=%d images=%d", requests.Load(), resolver.calls)
			}
			cfg.K3s.S3Endpoint = "https://s3.example.test"
			cfg.K3s.S3Region = "test"
			cfg.K3s.S3Secret = "credentials"
			cfg.BucketName = "snapshots"
			if err := entry.run(env); err == nil || !strings.Contains(err.Error(), reached.Error()) {
				t.Fatalf("valid S3 error=%v, want API sentinel", err)
			}
			if requests.Load() < 1 || resolver.calls != 0 {
				t.Fatalf("valid S3 activity: requests=%d images=%d", requests.Load(), resolver.calls)
			}
		})
	}
}

func TestStrictPreflightChecksEachS3ReferenceBeforeRequests(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config.Config)
		want   string
	}{
		{"endpoint", func(c *config.Config) { c.K3s.S3Endpoint = "" }, missingStorageReferences},
		{"region", func(c *config.Config) { c.K3s.S3Region = "" }, missingStorageReferences},
		{"Secret", func(c *config.Config) { c.K3s.S3Secret = "" }, missingStorageReferences},
		{"bucket", func(c *config.Config) { c.BucketName = "" }, missingStorageReferences},
		{"HTTP", func(c *config.Config) { c.K3s.S3Endpoint = "http://s3.example.test" }, missingStorageReferences},
		{"malformed URL", func(c *config.Config) { c.K3s.S3Endpoint = "://broken" }, missingStorageReferences},
		{"missing host", func(c *config.Config) { c.K3s.S3Endpoint = "https:///bucket" }, missingStorageReferences},
		{"userinfo", func(c *config.Config) { c.K3s.S3Endpoint = "https://user@s3.example.test" }, missingStorageReferences},
		{"query", func(c *config.Config) { c.K3s.S3Endpoint = "https://s3.example.test?key=value" }, missingStorageReferences},
		{"fragment", func(c *config.Config) { c.K3s.S3Endpoint = "https://s3.example.test#fragment" }, missingStorageReferences},
		{"invalid Secret", func(c *config.Config) { c.K3s.S3Secret = "Invalid_Secret" }, "invalid k3s S3 Secret name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadCertificateConfig(t)
			cfg.K3s.S3Endpoint = "https://s3.example.test"
			cfg.K3s.S3Region = "test"
			cfg.K3s.S3Secret = "credentials"
			cfg.BucketName = "snapshots"
			tc.change(cfg)
			env, requests, resolver := guardedNativeEnv(t, cfg, errors.New("unexpected API"))
			if err := env.PreflightK3s(context.Background(), false, config.ValidationStrict); err == nil || err.Error() != tc.want {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
			if requests.Load() != 0 || resolver.calls != 0 {
				t.Fatal("strict preflight attempted an effect")
			}
		})
	}
}

func TestDirectCSINoneAndErrorOrderArePreserved(t *testing.T) {
	cfg := loadCertificateConfig(t)
	env, requests, resolver := guardedNativeEnv(t, cfg, errors.New("unexpected API"))
	for _, driver := range []string{"none", "false", ""} {
		if err := env.SetupCSI(context.Background(), driver); err != nil {
			t.Fatalf("driver %q: %v", driver, err)
		}
	}
	if err := env.SetupCSI(context.Background(), "typo"); err == nil || err.Error() != `unknown CSI driver "typo" (valid options: nfs, hostpath, both, none)` {
		t.Fatalf("invalid driver error=%v", err)
	}
	if err := env.DeployAteSystem(context.Background(), DeployOptions{SetupCSI: "typo"}); err == nil || err.Error() != `unknown CSI driver "typo" (valid options: nfs, hostpath, both, none)` {
		t.Fatalf("system driver order error=%v", err)
	}
	if requests.Load() != 0 || resolver.calls != 0 {
		t.Fatal("no-op or invalid options attempted an effect")
	}
	env.Cfg = &config.Config{}
	if err := env.SetupCSI(context.Background(), "none"); err != nil {
		t.Fatal(err)
	}
	if err := env.PreflightK3s(context.Background(), true, config.ValidationStrict); err != nil {
		t.Fatal(err)
	}
}

func TestBenchmarkBoundaryRejectsMissingS3BeforeScripts(t *testing.T) {
	for _, sandbox := range []string{config.SandboxClassGvisor, config.SandboxClassMicrovm} {
		t.Run(sandbox, func(t *testing.T) {
			cfg := loadCertificateConfig(t)
			cfg.Root = t.TempDir()
			for _, script := range []string{deployLocustScript, installMicrovmDepScript} {
				path := cfg.Path(script)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf script-reached > marker\nexit 47\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			env, requests, resolver := guardedNativeEnv(t, cfg, errors.New("unexpected API"))
			opts := BenchmarkOptions{WorkerCount: 1, SandboxClass: sandbox}
			if err := env.DeployBenchmarks(context.Background(), opts); err == nil || err.Error() != missingStorageReferences {
				t.Fatalf("benchmark error=%v", err)
			}
			if _, err := os.Stat(cfg.Path("marker")); !os.IsNotExist(err) {
				t.Fatalf("script marker before validation: %v", err)
			}
			cfg.K3s.S3Endpoint = "https://s3.example.test"
			cfg.K3s.S3Region = "test"
			cfg.K3s.S3Secret = "credentials"
			cfg.BucketName = "snapshots"
			if err := env.DeployBenchmarks(context.Background(), opts); err == nil {
				t.Fatal("fixture script exit was lost")
			}
			marker, err := os.ReadFile(cfg.Path("marker"))
			if err != nil || string(marker) != "script-reached" {
				t.Fatalf("valid S3 script marker=%q, error=%v", marker, err)
			}
			if requests.Load() != 0 || resolver.calls != 0 {
				t.Fatal("benchmark attempted API/image activity")
			}
		})
	}
}

func TestSystemPreliminaryErrorsStillPrecedeS3Validation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Env)
		want   string
	}{
		{"namespace", func(e *Env) { e.Cfg.Namespace = "other" }, "deploy ate-system cannot be used with ATE_NAMESPACE=other: manifests/ate-install/ names ate-system literally; install into another namespace with a deployment that renders them, and use ate-setup only for the create steps"},
		{"version", func(e *Env) {
			e.substrateVersion = ""
			e.Cfg.Images = images.Source{Repo: "example.test/substrate", Tag: "invalid/version"}
		}, `build version "invalid/version" is not a valid label value (it would sanitize to "invalid-version"); pin a label-safe one with the VERSION env var`},
		{"provider", func(e *Env) { e.Cfg.CredentialProviderJSON = `{"enabled":false,"name":"forbidden"}` }, `invalid --credential-provider '{"enabled":false,"name":"forbidden"}': enabled false takes no name or address`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VERSION", "")
			cfg := loadCertificateConfig(t)
			env, requests, resolver := guardedNativeEnv(t, cfg, errors.New("unexpected API"))
			tc.change(env)
			if err := env.DeployAteSystem(context.Background(), DeployOptions{SetupCSI: "none"}); err == nil || err.Error() != tc.want {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
			if requests.Load() != 0 || resolver.calls != 0 {
				t.Fatal("invalid preliminary options attempted an effect")
			}
		})
	}
}
