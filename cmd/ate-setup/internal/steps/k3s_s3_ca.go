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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	s3CAConfigMap = "ate-s3-ca"
	s3CAKey       = "ca.pem"
	s3CAVolume    = "ate-s3-ca"
	s3CAPath      = "/run/ate-s3-ca/ca.pem"
	s3CAHashKey   = "ate.dev/s3-ca-sha256"
	s3CAOwnerKey  = "ate.dev/managed-by"
	s3CAOwner     = "ate-setup-s3-ca"
)

type s3CAPlan struct {
	pem  []byte
	hash string
}

func isK3sS3CATarget(obj *unstructured.Unstructured, container map[string]interface{}) bool {
	return obj.GetKind() == "Deployment" && obj.GetName() == "ate-api-server" && container["name"] == "ate-api-server" ||
		obj.GetKind() == "DaemonSet" && strings.HasPrefix(obj.GetName(), "atelet-") && container["name"] == "atelet"
}

func (e *Env) prepareK3sS3CA() error {
	e.s3CA = nil
	if e.Cfg.K3s == nil || e.Cfg.K3s.S3CAFile == "" {
		return nil
	}
	path := e.Cfg.K3s.S3CAFile
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("read k3s S3 CA file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return fmt.Errorf("k3s S3 CA file %q must be a regular file no larger than 1 MiB", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open k3s S3 CA file %q: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return fmt.Errorf("read k3s S3 CA file %q: %w", path, err)
	}
	if len(data) > 1<<20 || !validS3CAPEM(data, time.Now()) {
		return fmt.Errorf("k3s S3 CA file %q must contain only current public PEM certificates, no keys or other data", path)
	}
	hash := sha256.Sum256(data)
	e.s3CA = &s3CAPlan{pem: data, hash: hex.EncodeToString(hash[:])}
	return nil
}

func validS3CAPEM(data []byte, now time.Time) bool {
	count := 0
	for len(data) > 0 {
		data = bytes.TrimSpace(data)
		if len(data) == 0 {
			break
		}
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return false
		}
		count++
		data = rest
	}
	return count > 0
}

func (e *Env) reconcileK3sS3CA(ctx context.Context, full bool) error {
	if e.s3CA == nil {
		return nil
	}
	client := e.Kube.Typed.CoreV1().ConfigMaps(e.Namespace())
	current, err := client.Get(ctx, s3CAConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = client.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: s3CAConfigMap, Namespace: e.Namespace(), Labels: map[string]string{s3CAOwnerKey: s3CAOwner}},
			BinaryData: map[string][]byte{s3CAKey: e.s3CA.pem},
		}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if current.Labels[s3CAOwnerKey] != s3CAOwner || len(current.Data) != 0 || len(current.BinaryData) != 1 {
		return fmt.Errorf("ConfigMap %s/%s is not the installer-owned public S3 CA object", e.Namespace(), s3CAConfigMap)
	}
	previous, ok := current.BinaryData[s3CAKey]
	if !ok {
		return fmt.Errorf("ConfigMap %s/%s has a conflicting CA key", e.Namespace(), s3CAConfigMap)
	}
	if bytes.Equal(previous, e.s3CA.pem) {
		return nil
	}
	if !full {
		return fmt.Errorf("changing the shared S3 CA requires a full deploy ate-system operation")
	}
	current.BinaryData[s3CAKey] = e.s3CA.pem
	_, err = client.Update(ctx, current, metav1.UpdateOptions{})
	return err
}

func addK3sS3CAProjection(obj *unstructured.Unstructured, container map[string]interface{}, ca *s3CAPlan) error {
	if ca == nil {
		return nil
	}
	volume := map[string]interface{}{"name": s3CAVolume, "configMap": map[string]interface{}{"name": s3CAConfigMap, "items": []interface{}{map[string]interface{}{"key": s3CAKey, "path": s3CAKey}}}}
	volumes, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "volumes")
	if err != nil {
		return err
	}
	volumes, err = appendReserved(volumes, volume, s3CAVolume)
	if err != nil {
		return err
	}
	if err := unstructured.SetNestedSlice(obj.Object, volumes, "spec", "template", "spec", "volumes"); err != nil {
		return err
	}
	mount := map[string]interface{}{"name": s3CAVolume, "mountPath": "/run/ate-s3-ca", "readOnly": true}
	mounts, _ := container["volumeMounts"].([]interface{})
	mounts, err = appendReserved(mounts, mount, s3CAVolume)
	if err != nil {
		return err
	}
	container["volumeMounts"] = mounts
	env, _ := container["env"].([]interface{})
	env, err = appendReserved(env, map[string]interface{}{"name": "AWS_CA_BUNDLE", "value": s3CAPath}, "AWS_CA_BUNDLE")
	if err != nil {
		return err
	}
	container["env"] = env
	annotations, _, err := unstructured.NestedStringMap(obj.Object, "spec", "template", "metadata", "annotations")
	if err != nil {
		return err
	}
	if annotations == nil {
		annotations = make(map[string]string)
	}
	if prior, exists := annotations[s3CAHashKey]; exists && prior != ca.hash {
		return fmt.Errorf("conflicting pod-template annotation %s", s3CAHashKey)
	}
	annotations[s3CAHashKey] = ca.hash
	return unstructured.SetNestedStringMap(obj.Object, annotations, "spec", "template", "metadata", "annotations")
}

func appendReserved(items []interface{}, desired map[string]interface{}, name string) ([]interface{}, error) {
	found := false
	for _, item := range items {
		actual := item.(map[string]interface{})
		if actual["name"] != name {
			continue
		}
		if found || !reflect.DeepEqual(actual, desired) {
			return nil, fmt.Errorf("conflicting reserved entry %s", name)
		}
		found = true
	}
	if found {
		return items, nil
	}
	return append(items, desired), nil
}
