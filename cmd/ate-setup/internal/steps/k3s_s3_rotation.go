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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// S3RotationExpected is a read-only snapshot taken before a rotation.
// TemplateSHA256 covers the full Pod template, not just the CA annotation.
type S3RotationExpected struct {
	Context           string             `json:"context"`
	Namespace         string             `json:"namespace"`
	CAUID             string             `json:"caUID"`
	CAResourceVersion string             `json:"caResourceVersion"`
	CASHA256          string             `json:"caSHA256"`
	CAPEM             []byte             `json:"caPEM"`
	Endpoint          string             `json:"endpoint"`
	Clients           []S3RotationClient `json:"clients"`
}

type S3RotationClient struct {
	Kind            string   `json:"kind"`
	Name            string   `json:"name"`
	UID             string   `json:"uid"`
	ResourceVersion string   `json:"resourceVersion"`
	TemplateSHA256  string   `json:"templateSHA256"`
	PodUIDs         []string `json:"podUIDs"`
}

type S3TrustRotation struct {
	Expected    S3RotationExpected
	CAPEM       []byte
	ReceiptPath string
}

type S3RotationReceipt struct {
	Phase          string             `json:"phase"`
	Expected       S3RotationExpected `json:"expected"`
	TargetCASHA256 string             `json:"targetCASHA256"`
	TargetEndpoint string             `json:"targetEndpoint"`
	Observed       []S3RotationClient `json:"observed"`
	CompletedAt    time.Time          `json:"completedAt"`
}

type s3RotationWorkload struct {
	identity   S3RotationClient
	template   corev1.PodTemplateSpec
	deployment *appsv1.Deployment
	daemonSet  *appsv1.DaemonSet
}

func rotationHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func rotationTemplateHash(template corev1.PodTemplateSpec) string {
	data, _ := json.Marshal(template)
	return rotationHash(data)
}

func (e *Env) readS3RotationWorkloads(ctx context.Context) ([]s3RotationWorkload, error) {
	ns := e.Namespace()
	api, err := e.Kube.Typed.AppsV1().Deployments(ns).Get(ctx, "ate-api-server", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	dss, err := e.Kube.Typed.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := []s3RotationWorkload{{identity: S3RotationClient{Kind: "Deployment", Name: api.Name, UID: string(api.UID), ResourceVersion: api.ResourceVersion, TemplateSHA256: rotationTemplateHash(api.Spec.Template)}, template: api.Spec.Template, deployment: api}}
	for i := range dss.Items {
		ds := &dss.Items[i]
		if !strings.HasPrefix(ds.Name, "atelet-") {
			continue
		}
		out = append(out, s3RotationWorkload{identity: S3RotationClient{Kind: "DaemonSet", Name: ds.Name, UID: string(ds.UID), ResourceVersion: ds.ResourceVersion, TemplateSHA256: rotationTemplateHash(ds.Spec.Template)}, template: ds.Spec.Template, daemonSet: ds})
	}
	if len(out) == 1 {
		return nil, fmt.Errorf("no atelet DaemonSet exists")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].identity.Name < out[j].identity.Name })
	return out, nil
}

func (e *Env) InspectS3Rotation(ctx context.Context) (S3RotationExpected, error) {
	var result S3RotationExpected
	if e.Cfg == nil || e.Cfg.K3s == nil {
		return result, fmt.Errorf("S3 rotation requires a k3s profile")
	}
	cm, err := e.Kube.Typed.CoreV1().ConfigMaps(e.Namespace()).Get(ctx, s3CAConfigMap, metav1.GetOptions{})
	if err != nil {
		return result, err
	}
	if err := validateRotationCA(cm); err != nil {
		return result, err
	}
	workloads, err := e.readS3RotationWorkloads(ctx)
	if err != nil {
		return result, err
	}
	result = S3RotationExpected{Context: e.Cfg.Context, Namespace: e.Namespace(), CAUID: string(cm.UID), CAResourceVersion: cm.ResourceVersion, CASHA256: rotationHash(cm.BinaryData[s3CAKey]), CAPEM: cm.BinaryData[s3CAKey], Endpoint: e.Cfg.K3s.S3Endpoint}
	for _, workload := range workloads {
		if err := checkRotationTemplate(workload.template, result.CASHA256, result.Endpoint); err != nil {
			return S3RotationExpected{}, fmt.Errorf("%s: %w", workload.identity.Name, err)
		}
		identity := workload.identity
		pods, err := e.rotationPods(ctx, workload)
		if err != nil {
			return S3RotationExpected{}, err
		}
		for _, pod := range pods {
			identity.PodUIDs = append(identity.PodUIDs, string(pod.UID))
		}
		sort.Strings(identity.PodUIDs)
		if len(identity.PodUIDs) == 0 {
			return S3RotationExpected{}, fmt.Errorf("%s has no running Pods", identity.Name)
		}
		result.Clients = append(result.Clients, identity)
	}
	return result, nil
}

func (e *Env) rotationPods(ctx context.Context, workload s3RotationWorkload) ([]corev1.Pod, error) {
	var selector *metav1.LabelSelector
	if workload.deployment != nil {
		selector = workload.deployment.Spec.Selector
	} else {
		selector = workload.daemonSet.Spec.Selector
	}
	if selector == nil {
		return nil, fmt.Errorf("%s has no Pod selector", workload.identity.Name)
	}
	query, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, err
	}
	pods, err := e.Kube.Typed.CoreV1().Pods(e.Namespace()).List(ctx, metav1.ListOptions{LabelSelector: query.String()})
	if err != nil {
		return nil, err
	}
	var selected []corev1.Pod
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp == nil {
			selected = append(selected, pod)
		}
	}
	return selected, nil
}

func validateRotationCA(cm *corev1.ConfigMap) error {
	if cm.Labels[s3CAOwnerKey] != s3CAOwner || len(cm.Data) != 0 || len(cm.BinaryData) != 1 || len(cm.BinaryData[s3CAKey]) == 0 {
		return fmt.Errorf("S3 CA ConfigMap is not the installer-owned public CA object")
	}
	return nil
}

func checkRotationTemplate(template corev1.PodTemplateSpec, hash, endpoint string) error {
	if template.Annotations[s3CAHashKey] != hash {
		return fmt.Errorf("CA template hash mismatch")
	}
	if len(template.Spec.Containers) == 0 {
		return fmt.Errorf("missing client container")
	}
	foundEndpoint, foundBundle := false, false
	for _, container := range template.Spec.Containers {
		for _, entry := range container.Env {
			if entry.Name == "AWS_ENDPOINT_URL" && entry.Value == endpoint && entry.ValueFrom == nil {
				foundEndpoint = true
			}
			if entry.Name == "AWS_CA_BUNDLE" && entry.Value == s3CAPath && entry.ValueFrom == nil {
				foundBundle = true
			}
		}
	}
	if !foundEndpoint || !foundBundle {
		return fmt.Errorf("S3 endpoint or CA projection mismatch")
	}
	return nil
}

func (e *Env) RotateS3Trust(ctx context.Context, req S3TrustRotation) (S3RotationReceipt, error) {
	var receipt S3RotationReceipt
	if req.ReceiptPath == "" || !filepath.IsAbs(req.ReceiptPath) || filepath.Clean(req.ReceiptPath) != req.ReceiptPath {
		return receipt, fmt.Errorf("rotation receipt needs a clean absolute path")
	}
	if _, err := os.Lstat(req.ReceiptPath); err == nil {
		return receipt, fmt.Errorf("rotation receipt already exists")
	} else if !os.IsNotExist(err) {
		return receipt, err
	}
	if len(req.CAPEM) > 1<<20 || !validS3CAPEM(req.CAPEM, time.Now()) {
		return receipt, fmt.Errorf("overlap CA must contain only current public certificates")
	}
	if req.Expected.Context != e.Cfg.Context || req.Expected.Namespace != e.Namespace() || e.Cfg.K3s == nil || req.Expected.Endpoint != e.Cfg.K3s.S3Endpoint {
		return receipt, fmt.Errorf("rotation cluster or endpoint does not match the configured k3s profile")
	}
	cm, err := e.Kube.Typed.CoreV1().ConfigMaps(e.Namespace()).Get(ctx, s3CAConfigMap, metav1.GetOptions{})
	if err != nil {
		return receipt, err
	}
	if err := validateRotationCA(cm); err != nil {
		return receipt, err
	}
	if string(cm.UID) != req.Expected.CAUID {
		return receipt, fmt.Errorf("S3 CA ConfigMap UID changed")
	}
	oldHash, targetHash := req.Expected.CASHA256, rotationHash(req.CAPEM)
	if rotationHash(req.Expected.CAPEM) != oldHash || !validS3CAPEM(req.Expected.CAPEM, time.Now()) {
		return receipt, fmt.Errorf("expected old public CA is invalid")
	}
	oldCA := cm.BinaryData[s3CAKey]
	if !bytes.Equal(oldCA, req.Expected.CAPEM) && !bytes.Equal(oldCA, req.CAPEM) {
		return receipt, fmt.Errorf("S3 CA is neither expected old nor target")
	}
	if rotationHash(oldCA) == oldHash && cm.ResourceVersion != req.Expected.CAResourceVersion {
		return receipt, fmt.Errorf("S3 CA resource version changed")
	}
	if !validS3CAPEM(oldCA, time.Now()) {
		return receipt, fmt.Errorf("old public CA has expired")
	}
	if targetHash == oldHash || !bytes.Contains(req.CAPEM, bytes.TrimSpace(req.Expected.CAPEM)) || !validS3CAPEM(bytes.Replace(req.CAPEM, bytes.TrimSpace(req.Expected.CAPEM), nil, 1), time.Now()) {
		return receipt, fmt.Errorf("overlap CA must contain old and new public certificates")
	}
	workloads, err := e.readS3RotationWorkloads(ctx)
	if err != nil {
		return receipt, err
	}
	if len(workloads) != len(req.Expected.Clients) {
		return receipt, fmt.Errorf("S3 client set changed")
	}
	for i, workload := range workloads {
		want := req.Expected.Clients[i]
		if workload.identity.Kind != want.Kind || workload.identity.Name != want.Name || workload.identity.UID != want.UID {
			return receipt, fmt.Errorf("S3 client identity changed")
		}
		if workload.identity.TemplateSHA256 == want.TemplateSHA256 {
			if workload.identity.ResourceVersion != want.ResourceVersion {
				return receipt, fmt.Errorf("%s resource version changed", want.Name)
			}
			if err := checkRotationTemplate(workload.template, oldHash, req.Expected.Endpoint); err != nil {
				return receipt, err
			}
		} else {
			target := workload.template.DeepCopy()
			target.Annotations[s3CAHashKey] = oldHash
			if rotationTemplateHash(*target) != want.TemplateSHA256 {
				return receipt, fmt.Errorf("%s has an unknown Pod template", want.Name)
			}
			if err := checkRotationTemplate(workload.template, targetHash, req.Expected.Endpoint); err != nil {
				return receipt, fmt.Errorf("%s is not a known rotation state: %w", want.Name, err)
			}
		}
	}
	if !bytes.Equal(oldCA, req.CAPEM) {
		cm.BinaryData[s3CAKey] = req.CAPEM
		if _, err := e.Kube.Typed.CoreV1().ConfigMaps(e.Namespace()).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return receipt, e.stoppedS3TrustUpdate(ctx, req, targetHash, "S3 CA", err)
		}
	}
	for _, workload := range workloads {
		if workload.template.Annotations[s3CAHashKey] == targetHash {
			continue
		}
		if workload.deployment != nil {
			obj := workload.deployment.DeepCopy()
			obj.Spec.Template.Annotations[s3CAHashKey] = targetHash
			if _, err := e.Kube.Typed.AppsV1().Deployments(e.Namespace()).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				return receipt, e.stoppedS3TrustUpdate(ctx, req, targetHash, obj.Name, err)
			}
		} else {
			obj := workload.daemonSet.DeepCopy()
			obj.Spec.Template.Annotations[s3CAHashKey] = targetHash
			if _, err := e.Kube.Typed.AppsV1().DaemonSets(e.Namespace()).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				return receipt, e.stoppedS3TrustUpdate(ctx, req, targetHash, obj.Name, err)
			}
		}
	}
	observed, err := e.readS3RotationWorkloads(ctx)
	if err != nil {
		return receipt, err
	}
	for _, workload := range observed {
		if err := checkRotationTemplate(workload.template, targetHash, req.Expected.Endpoint); err != nil {
			return receipt, fmt.Errorf("%s target observation: %w", workload.identity.Name, err)
		}
		identity := workload.identity
		identity.PodUIDs, err = e.waitS3RotationPods(ctx, workload, req.Expected.Clients, targetHash)
		if err != nil {
			observeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return receipt, e.stoppedS3TrustUpdate(observeCtx, req, targetHash, workload.identity.Name+" rollout", err)
		}
		receipt.Observed = append(receipt.Observed, identity)
	}
	finalCA, err := e.Kube.Typed.CoreV1().ConfigMaps(e.Namespace()).Get(ctx, s3CAConfigMap, metav1.GetOptions{})
	if err != nil {
		return receipt, err
	}
	if string(finalCA.UID) != req.Expected.CAUID || !bytes.Equal(finalCA.BinaryData[s3CAKey], req.CAPEM) {
		return receipt, fmt.Errorf("S3 CA target observation failed")
	}
	receipt.Phase, receipt.Expected, receipt.TargetCASHA256, receipt.TargetEndpoint, receipt.CompletedAt = "trust", req.Expected, targetHash, req.Expected.Endpoint, time.Now().UTC()
	if err := writeS3RotationReceipt(req.ReceiptPath, receipt); err != nil {
		return S3RotationReceipt{}, err
	}
	return receipt, nil
}

func (e *Env) stoppedS3TrustUpdate(ctx context.Context, req S3TrustRotation, targetHash, resource string, updateErr error) error {
	state, observeErr := e.observeS3TrustState(ctx, req, targetHash)
	if observeErr != nil {
		return fmt.Errorf("%s update stopped; outcome unknown because observation failed (%v): %w", resource, observeErr, updateErr)
	}
	return fmt.Errorf("%s update stopped; observed %s state, no retry attempted: %w", resource, state, updateErr)
}

func (e *Env) observeS3TrustState(ctx context.Context, req S3TrustRotation, targetHash string) (string, error) {
	cm, err := e.Kube.Typed.CoreV1().ConfigMaps(e.Namespace()).Get(ctx, s3CAConfigMap, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if err := validateRotationCA(cm); err != nil {
		return "", err
	}
	if string(cm.UID) != req.Expected.CAUID {
		return "", fmt.Errorf("CA UID changed")
	}
	oldHash := req.Expected.CASHA256
	cmState := "old"
	if bytes.Equal(cm.BinaryData[s3CAKey], req.CAPEM) {
		cmState = "target"
	} else if !bytes.Equal(cm.BinaryData[s3CAKey], req.Expected.CAPEM) {
		return "", fmt.Errorf("CA bytes are unknown")
	}
	workloads, err := e.readS3RotationWorkloads(ctx)
	if err != nil {
		return "", err
	}
	if len(workloads) != len(req.Expected.Clients) {
		return "", fmt.Errorf("client set changed")
	}
	oldClients, targetClients := 0, 0
	for i, workload := range workloads {
		want := req.Expected.Clients[i]
		if workload.identity.Kind != want.Kind || workload.identity.Name != want.Name || workload.identity.UID != want.UID {
			return "", fmt.Errorf("client identity changed")
		}
		if workload.identity.TemplateSHA256 == want.TemplateSHA256 {
			oldClients++
			if err := checkRotationTemplate(workload.template, oldHash, req.Expected.Endpoint); err != nil {
				return "", err
			}
			continue
		}
		target := workload.template.DeepCopy()
		target.Annotations[s3CAHashKey] = oldHash
		if rotationTemplateHash(*target) != want.TemplateSHA256 {
			return "", fmt.Errorf("%s template is unknown", want.Name)
		}
		if err := checkRotationTemplate(workload.template, targetHash, req.Expected.Endpoint); err != nil {
			return "", err
		}
		targetClients++
	}
	if cmState == "old" && oldClients == len(workloads) {
		return "old", nil
	}
	if cmState == "target" && targetClients == len(workloads) {
		return "target", nil
	}
	return "partial", nil
}

func (e *Env) waitS3RotationPods(ctx context.Context, workload s3RotationWorkload, expected []S3RotationClient, hash string) ([]string, error) {
	var old []string
	for _, client := range expected {
		if client.Kind == workload.identity.Kind && client.Name == workload.identity.Name {
			old = client.PodUIDs
			break
		}
	}
	if len(old) == 0 {
		return nil, fmt.Errorf("%s has no expected Pod UIDs", workload.identity.Name)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		pods, err := e.rotationPods(waitCtx, workload)
		if err != nil {
			return nil, err
		}
		newPods := 0
		oldPod := false
		allReady := true
		var uids []string
		for _, pod := range pods {
			uid := string(pod.UID)
			uids = append(uids, uid)
			found := false
			for _, prior := range old {
				if prior == uid {
					found = true
					break
				}
			}
			if found {
				oldPod = true
			} else if pod.Annotations[s3CAHashKey] == hash && podReady(&pod) {
				newPods++
			} else {
				allReady = false
			}
		}
		sort.Strings(uids)
		if newPods >= len(old) && !oldPod && allReady {
			current, err := e.readS3RotationWorkloads(waitCtx)
			if err != nil {
				return nil, err
			}
			for _, item := range current {
				if item.identity.Name == workload.identity.Name && item.identity.Kind == workload.identity.Kind {
					if err := checkRotationTemplate(item.template, hash, e.Cfg.K3s.S3Endpoint); err != nil {
						return nil, err
					}
					if rotationWorkloadReady(item) {
						return uids, nil
					}
				}
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("%s rollout outcome uncertain: %w", workload.identity.Name, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func rotationWorkloadReady(workload s3RotationWorkload) bool {
	if workload.deployment != nil {
		deployment := workload.deployment
		want := int32(1)
		if deployment.Spec.Replicas != nil {
			want = *deployment.Spec.Replicas
		}
		return want > 0 && deployment.Status.ObservedGeneration >= deployment.Generation && deployment.Status.UpdatedReplicas >= want && deployment.Status.AvailableReplicas >= want
	}
	ds := workload.daemonSet
	want := ds.Status.DesiredNumberScheduled
	return want > 0 && ds.Status.ObservedGeneration >= ds.Generation && ds.Status.UpdatedNumberScheduled >= want && ds.Status.NumberAvailable >= want
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func writeS3RotationReceipt(path string, receipt S3RotationReceipt) error {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".s3-rotation-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Link(f.Name(), path)
}
