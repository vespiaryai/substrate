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
	"net/url"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

type K3sProfile struct{ Node, NodeUID, SystemUID, KubeletRoot, S3Endpoint, S3Region, S3Secret, S3CAFile, SnapshotController, SnapshotControllerUID string }

func (c *Config) ValidateK3s() error {
	if c.K3s == nil {
		return nil
	}
	p := c.K3s
	if c.Kind {
		return fmt.Errorf("--kind and --k3s are mutually exclusive")
	}
	if c.Kubeconfig == "" || c.Context == "" || p.Node == "" || p.NodeUID == "" || p.SystemUID == "" {
		return fmt.Errorf("k3s requires explicit kubeconfig, context, node, node UID and kube-system UID")
	}
	if !filepath.IsAbs(p.KubeletRoot) || filepath.Clean(p.KubeletRoot) != p.KubeletRoot || p.KubeletRoot == "/" || strings.ContainsAny(p.KubeletRoot, " \t\n") {
		return fmt.Errorf("k3s requires a clean absolute kubelet root")
	}
	if c.Router != RouterEnvoy || c.ClusterSize != ClusterSizeSize0 || c.CordonControlPlane || c.ProjectID != "" || c.ClusterName != "" || c.ClusterLocation != "" || c.CloudSQL.Instance != "" {
		return fmt.Errorf("k3s supports only size0, envoy and a local single-node profile without GCP or cordon options")
	}
	u, err := url.Parse(p.S3Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || p.S3Region == "" || p.S3Secret == "" || c.BucketName == "" {
		return fmt.Errorf("k3s requires an explicit HTTPS S3 endpoint, region, bucket and existing credential Secret")
	}
	if len(validation.IsDNS1123Subdomain(p.S3Secret)) != 0 {
		return fmt.Errorf("invalid k3s S3 Secret name")
	}
	if p.S3CAFile != "" && (!filepath.IsAbs(p.S3CAFile) || filepath.Clean(p.S3CAFile) != p.S3CAFile) {
		return fmt.Errorf("k3s S3 CA file must be a clean absolute path")
	}
	return nil
}
