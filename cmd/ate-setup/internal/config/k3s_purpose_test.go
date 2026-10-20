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

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
)

func nativeValidationConfig() *Config {
	return &Config{Kubeconfig: "/explicit/config", Context: "local", Router: RouterEnvoy, ClusterSize: ClusterSizeSize0, BucketName: "snapshots", K3s: &K3sProfile{Node: "node-a", NodeUID: "node-uid", SystemUID: "system-uid", KubeletRoot: "/var/lib/kubelet", S3Endpoint: "https://s3.example.test", S3Region: "test", S3Secret: "credentials"}}
}

func TestValidationPurposeDefaultsStrict(t *testing.T) {
	for value := 0; value < 256; value++ {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			if err := nativeValidationConfig().ValidateK3s(ValidationPurpose(value)); err != nil {
				t.Fatalf("valid S3 with purpose %d: %v", value, err)
			}
			cfg := nativeValidationConfig()
			cfg.BucketName = ""
			err := cfg.ValidateK3s(ValidationPurpose(value))
			if value == int(ValidationCertificateBootstrap) {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.Error() != "k3s requires an explicit HTTPS S3 endpoint, region, bucket and existing credential Secret" {
				t.Fatalf("purpose %d error = %v", value, err)
			}
			if err := (&Config{}).ValidateK3s(ValidationPurpose(value)); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := nativeValidationConfig().ValidateK3s(ValidationStrict); err != nil {
		t.Fatal(err)
	}
}

func TestCertificatePurposeKeepsEveryCommonConfigurationCheck(t *testing.T) {
	const identity = "k3s requires explicit kubeconfig, context, node, node UID and kube-system UID"
	const root = "k3s requires a clean absolute kubelet root"
	const profile = "k3s supports only size0, envoy and a local single-node profile without GCP or cordon options"
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"kind", func(c *Config) { c.Kind = true }, "--kind and --k3s are mutually exclusive"},
		{"kubeconfig", func(c *Config) { c.Kubeconfig = "" }, identity},
		{"context", func(c *Config) { c.Context = "" }, identity},
		{"node", func(c *Config) { c.K3s.Node = "" }, identity},
		{"node UID", func(c *Config) { c.K3s.NodeUID = "" }, identity},
		{"system UID", func(c *Config) { c.K3s.SystemUID = "" }, identity},
		{"relative root", func(c *Config) { c.K3s.KubeletRoot = "relative" }, root},
		{"filesystem root", func(c *Config) { c.K3s.KubeletRoot = "/" }, root},
		{"unclean root", func(c *Config) { c.K3s.KubeletRoot = "/var/../kubelet" }, root},
		{"whitespace root", func(c *Config) { c.K3s.KubeletRoot = "/var/lib/kube let" }, root},
		{"size", func(c *Config) { c.ClusterSize = ClusterSizeSize10 }, profile},
		{"router", func(c *Config) { c.Router = RouterAgentgateway }, profile},
		{"cordon", func(c *Config) { c.CordonControlPlane = true }, profile},
		{"project", func(c *Config) { c.ProjectID = "project" }, profile},
		{"cluster", func(c *Config) { c.ClusterName = "cluster" }, profile},
		{"location", func(c *Config) { c.ClusterLocation = "location" }, profile},
		{"Cloud SQL", func(c *Config) { c.CloudSQL.Instance = "instance" }, profile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nativeValidationConfig()
			cfg.K3s.S3Endpoint = ""
			cfg.BucketName = ""
			tc.change(cfg)
			if err := cfg.ValidateK3s(ValidationCertificateBootstrap); err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStrictS3ReferencesAndUnusedCertificateReferences(t *testing.T) {
	const missing = "k3s requires an explicit HTTPS S3 endpoint, region, bucket and existing credential Secret"
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"missing endpoint", func(c *Config) { c.K3s.S3Endpoint = "" }, missing},
		{"missing region", func(c *Config) { c.K3s.S3Region = "" }, missing},
		{"missing Secret", func(c *Config) { c.K3s.S3Secret = "" }, missing},
		{"missing bucket", func(c *Config) { c.BucketName = "" }, missing},
		{"HTTP", func(c *Config) { c.K3s.S3Endpoint = "http://s3.example.test" }, missing},
		{"malformed URL", func(c *Config) { c.K3s.S3Endpoint = "://broken" }, missing},
		{"missing host", func(c *Config) { c.K3s.S3Endpoint = "https:///bucket" }, missing},
		{"userinfo", func(c *Config) { c.K3s.S3Endpoint = "https://user@s3.example.test" }, missing},
		{"query", func(c *Config) { c.K3s.S3Endpoint = "https://s3.example.test?key=value" }, missing},
		{"fragment", func(c *Config) { c.K3s.S3Endpoint = "https://s3.example.test#fragment" }, missing},
		{"invalid Secret", func(c *Config) { c.K3s.S3Secret = "Invalid_Secret" }, "invalid k3s S3 Secret name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nativeValidationConfig()
			tc.change(cfg)
			if err := cfg.ValidateK3s(ValidationStrict); err == nil || err.Error() != tc.want {
				t.Fatalf("strict error = %v, want %q", err, tc.want)
			}
			if err := cfg.ValidateK3s(ValidationCertificateBootstrap); err != nil {
				t.Fatalf("unused certificate reference: %v", err)
			}
		})
	}
}

func TestNativePurposeLoadPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		file, flags bool
		empty       string
		wantErr     string
	}{
		{name: "environment"}, {name: "file", file: true}, {name: "flags", file: true, flags: true},
		{name: "empty flag context", file: true, flags: true, empty: "context", wantErr: "k3s requires explicit kubeconfig, context, node, node UID and kube-system UID"},
		{name: "empty flag endpoint", file: true, flags: true, empty: "k3s-s3-endpoint", wantErr: "k3s requires an explicit HTTPS S3 endpoint, region, bucket and existing credential Secret"},
		{name: "empty file endpoint", file: true, empty: "file endpoint", wantErr: "k3s requires an explicit HTTPS S3 endpoint, region, bucket and existing credential Secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, s := range All() {
				if s.Env != "" {
					unsetEnv(t, s.Env)
				}
			}
			unsetEnv(t, ConfigPathEnv)
			for key, value := range map[string]string{"ATE_INSTALL_K3S": "true", "KUBECONFIG": "/explicit/config", "KUBECTL_CONTEXT": "env-context", "ATE_K3S_NODE": "env-node", "ATE_K3S_NODE_UID": "node-uid", "ATE_K3S_SYSTEM_UID": "system-uid", "ATE_K3S_KUBELET_ROOT": "/var/lib/kubelet", "ATE_INSTALL_CLUSTER_SIZE": "size0", "ATE_ATENET_DATAPLANE": "envoy", "ATE_K3S_S3_ENDPOINT": "https://env.example.test", "ATE_K3S_S3_REGION": "env-region", "ATE_K3S_S3_SECRET": "env-secret", "BUCKET_NAME": "env-bucket"} {
				t.Setenv(key, value)
			}
			fs := pflag.NewFlagSet(tc.name, pflag.ContinueOnError)
			BindFlags(fs)
			options := LoadOptions{NoDevEnv: true}
			want := "env"
			if tc.file {
				endpoint := "https://file.example.test"
				if tc.empty == "file endpoint" {
					endpoint = ""
				}
				body := fmt.Sprintf("apiVersion: %s\nkind: %s\ncontext: file-context\nk3s:\n  node: file-node\n  s3Endpoint: %q\n  s3Region: file-region\n  s3Secret: file-secret\nstorage:\n  bucketName: file-bucket\n", FileAPIVersion, FileKind, endpoint)
				options.ConfigPath = filepath.Join(t.TempDir(), "config.yaml")
				if err := os.WriteFile(options.ConfigPath, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				want = "file"
			}
			if tc.flags {
				for flag, value := range map[string]string{"context": "flag-context", "k3s-node": "flag-node", "k3s-s3-endpoint": "https://flag.example.test", "k3s-s3-region": "flag-region", "k3s-s3-secret": "flag-secret", "storage-bucket-name": "flag-bucket"} {
					if err := fs.Set(flag, value); err != nil {
						t.Fatal(err)
					}
				}
				want = "flag"
				if tc.empty != "" {
					if err := fs.Set(tc.empty, ""); err != nil {
						t.Fatal(err)
					}
				}
			}
			cfg, err := LoadFlags(fs, options, ValidationStrict)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error=%v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Context != want+"-context" || cfg.K3s.Node != want+"-node" || cfg.K3s.S3Endpoint != "https://"+want+".example.test" || cfg.K3s.S3Region != want+"-region" || cfg.K3s.S3Secret != want+"-secret" || cfg.BucketName != want+"-bucket" {
				t.Fatalf("wrong resolved channel %s: %+v, %+v", want, cfg, cfg.K3s)
			}
		})
	}
}
