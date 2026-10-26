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
	"strings"
	"testing"
)

func TestK3sProfileRejectsUnsafeConfigurations(t *testing.T) {
	valid := func() *Config {
		return &Config{Kubeconfig: "/explicit/config", Context: "local", Router: RouterEnvoy, ClusterSize: ClusterSizeSize0, BucketName: "snapshots", K3s: &K3sProfile{Node: "fedora", NodeUID: "node-uid", SystemUID: "system-uid", KubeletRoot: "/var/lib/kubelet", S3Endpoint: "https://s3.example.test", S3Region: "test", S3Secret: "credentials"}}
	}
	if err := valid().ValidateK3s(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"Kind", func(c *Config) { c.Kind = true }},
		{"implicit context", func(c *Config) { c.Context = "" }},
		{"implicit kubeconfig", func(c *Config) { c.Kubeconfig = "" }},
		{"missing UID", func(c *Config) { c.K3s.NodeUID = "" }},
		{"unsafe root", func(c *Config) { c.K3s.KubeletRoot = "/" }},
		{"relative root", func(c *Config) { c.K3s.KubeletRoot = "var/lib/kubelet" }},
		{"cloud project", func(c *Config) { c.ProjectID = "inherited" }},
		{"plaintext snapshot service", func(c *Config) { c.K3s.S3Endpoint = "http://localhost:9000" }},
		{"missing credential Secret", func(c *Config) { c.K3s.S3Secret = "" }},
		{"relative CA file", func(c *Config) { c.K3s.S3CAFile = "relative.pem" }},
		{"unclean CA file", func(c *Config) { c.K3s.S3CAFile = "/tmp/../ca.pem" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.change(c)
			if err := c.ValidateK3s(); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestK3sSettingsBuildConfig(t *testing.T) {
	env := map[string]string{
		"ATE_INSTALL_K3S":                 "true",
		"ATE_INSTALL_KIND":                "false",
		"KUBECONFIG":                      "/explicit/fedora/config",
		"KUBECTL_CONTEXT":                 "fedora-local",
		"ATE_INSTALL_CLUSTER_SIZE":        "size0",
		"ATE_ATENET_DATAPLANE":            "envoy",
		"BUCKET_NAME":                     "fedora-snapshots",
		"ATE_K3S_NODE":                    "fedora",
		"ATE_K3S_NODE_UID":                "fedora-node-uid",
		"ATE_K3S_SYSTEM_UID":              "fedora-system-uid",
		"ATE_K3S_KUBELET_ROOT":            "/var/lib/kubelet",
		"ATE_K3S_S3_ENDPOINT":             "https://snapshots.example.test",
		"ATE_K3S_S3_REGION":               "local-region",
		"ATE_K3S_S3_SECRET":               "snapshot-credentials",
		"ATE_K3S_S3_CA_FILE":              "/public/ca.pem",
		"ATE_K3S_SNAPSHOT_CONTROLLER":     "snapshot-system/snapshot-controller",
		"ATE_K3S_SNAPSHOT_CONTROLLER_UID": "snapshot-controller-uid",
	}
	r, err := Resolve(nil, ResolveOptions{Env: env})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	cfg, err := buildConfig(t.TempDir(), env, r)
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}
	want := K3sProfile{
		Node:                  "fedora",
		NodeUID:               "fedora-node-uid",
		SystemUID:             "fedora-system-uid",
		KubeletRoot:           "/var/lib/kubelet",
		S3Endpoint:            "https://snapshots.example.test",
		S3Region:              "local-region",
		S3Secret:              "snapshot-credentials",
		S3CAFile:              "/public/ca.pem",
		SnapshotController:    "snapshot-system/snapshot-controller",
		SnapshotControllerUID: "snapshot-controller-uid",
	}
	if cfg.K3s == nil || *cfg.K3s != want {
		t.Fatalf("K3s = %+v, want %+v", cfg.K3s, want)
	}
	if cfg.Kubeconfig != "/explicit/fedora/config" || cfg.Context != "fedora-local" || cfg.BucketName != "fedora-snapshots" {
		t.Errorf("connection/storage = %q, %q, %q; want explicit Fedora settings", cfg.Kubeconfig, cfg.Context, cfg.BucketName)
	}
	if cfg.Kind || cfg.ProjectID != "" || cfg.ClusterName != "" || cfg.ClusterLocation != "" || cfg.CloudSQL.Instance != "" {
		t.Errorf("local profile contains Kind/GCP configuration: Kind=%v project=%q cluster=%q location=%q CloudSQL=%q", cfg.Kind, cfg.ProjectID, cfg.ClusterName, cfg.ClusterLocation, cfg.CloudSQL.Instance)
	}
}

func TestK3sS3CAFileChannels(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   map[string]string
		file  map[string]string
		flags map[string]string
		want  string
	}{
		{"unset", nil, nil, nil, ""},
		{"environment", map[string]string{"ATE_K3S_S3_CA_FILE": "/env.pem"}, nil, nil, "/env.pem"},
		{"file", map[string]string{"ATE_K3S_S3_CA_FILE": "/env.pem"}, map[string]string{"k3s.s3CAFile": "/file.pem"}, nil, "/file.pem"},
		{"flag", map[string]string{"ATE_K3S_S3_CA_FILE": "/env.pem"}, map[string]string{"k3s.s3CAFile": "/file.pem"}, map[string]string{"k3s-s3-ca-file": "/flag.pem"}, "/flag.pem"},
		{"empty file clears environment", map[string]string{"ATE_K3S_S3_CA_FILE": "/env.pem"}, map[string]string{"k3s.s3CAFile": ""}, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Resolve(flagsWith(t, tc.flags), ResolveOptions{Env: tc.env, File: fileWith(tc.file)})
			if err != nil {
				t.Fatal(err)
			}
			if got := r.String("k3s.s3CAFile"); got != tc.want {
				t.Fatalf("CA file = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestK3sS3CAFileRequiresProfile(t *testing.T) {
	r, err := Resolve(nil, ResolveOptions{Env: map[string]string{"ATE_K3S_S3_CA_FILE": "/public.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = buildConfig(t.TempDir(), nil, r)
	if err == nil || !strings.Contains(err.Error(), "ATE_K3S_S3_CA_FILE") {
		t.Fatalf("non-k3s CA input error = %v", err)
	}
}
