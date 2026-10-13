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

import "testing"

func TestK3sProfileRejectsUnsafeConfigurations(t *testing.T) {
	valid := func() *Config {
		return &Config{Kubeconfig: "/explicit/config", Context: "local", Router: RouterEnvoy, ClusterSize: ClusterSizeSize0, BucketName: "snapshots", K3s: &K3sProfile{Node: "node-a", NodeUID: "node-uid", SystemUID: "system-uid", KubeletRoot: "/var/lib/kubelet", S3Endpoint: "https://s3.example.test", S3Region: "test", S3Secret: "credentials"}}
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
		"KUBECONFIG":                      "/explicit/node-a/config",
		"KUBECTL_CONTEXT":                 "node-a-local",
		"ATE_INSTALL_CLUSTER_SIZE":        "size0",
		"ATE_ATENET_DATAPLANE":            "envoy",
		"BUCKET_NAME":                     "node-a-snapshots",
		"ATE_K3S_NODE":                    "node-a",
		"ATE_K3S_NODE_UID":                "node-a-node-uid",
		"ATE_K3S_SYSTEM_UID":              "node-a-system-uid",
		"ATE_K3S_KUBELET_ROOT":            "/var/lib/kubelet",
		"ATE_K3S_S3_ENDPOINT":             "https://snapshots.example.test",
		"ATE_K3S_S3_REGION":               "local-region",
		"ATE_K3S_S3_SECRET":               "snapshot-credentials",
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
		Node:                  "node-a",
		NodeUID:               "node-a-node-uid",
		SystemUID:             "node-a-system-uid",
		KubeletRoot:           "/var/lib/kubelet",
		S3Endpoint:            "https://snapshots.example.test",
		S3Region:              "local-region",
		S3Secret:              "snapshot-credentials",
		SnapshotController:    "snapshot-system/snapshot-controller",
		SnapshotControllerUID: "snapshot-controller-uid",
	}
	if cfg.K3s == nil || *cfg.K3s != want {
		t.Fatalf("K3s = %+v, want %+v", cfg.K3s, want)
	}
	if cfg.Kubeconfig != "/explicit/node-a/config" || cfg.Context != "node-a-local" || cfg.BucketName != "node-a-snapshots" {
		t.Errorf("connection/storage = %q, %q, %q; want explicit local k3s settings", cfg.Kubeconfig, cfg.Context, cfg.BucketName)
	}
	if cfg.Kind || cfg.ProjectID != "" || cfg.ClusterName != "" || cfg.ClusterLocation != "" || cfg.CloudSQL.Instance != "" {
		t.Errorf("local profile contains Kind/GCP configuration: Kind=%v project=%q cluster=%q location=%q CloudSQL=%q", cfg.Kind, cfg.ProjectID, cfg.ClusterName, cfg.ClusterLocation, cfg.CloudSQL.Instance)
	}
}
