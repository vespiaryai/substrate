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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kustomize"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (e *Env) PreflightK3s(ctx context.Context, csi bool) error {
	if e.Cfg.K3s == nil {
		return nil
	}
	if err := e.Cfg.ValidateK3s(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	p := e.Cfg.K3s
	ns, err := e.Kube.Typed.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("k3s cluster binding: %w", err)
	}
	if string(ns.UID) != p.SystemUID {
		return fmt.Errorf("kube-system UID does not match the approved k3s cluster")
	}
	nodes, err := e.Kube.Typed.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(nodes.Items) != 1 {
		return fmt.Errorf("k3s profile requires exactly one node")
	}
	n := nodes.Items[0]
	if err := validateK3sNode(n, p.Node, p.NodeUID); err != nil {
		return err
	}
	for gv, names := range map[string][]string{"certificates.k8s.io/v1beta1": {"podcertificaterequests", "clustertrustbundles"}} {
		if err := e.requireK3sResources(ctx, gv, names); err != nil {
			return err
		}
	}
	if !csi {
		return nil
	}
	if err := e.requireK3sResources(ctx, "snapshot.storage.k8s.io/v1", []string{"volumesnapshots", "volumesnapshotcontents", "volumesnapshotclasses"}); err != nil {
		return err
	}
	pvs, err := e.Kube.Typed.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	pvcs, err := e.Kube.Typed.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	attachments, err := e.Kube.Typed.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(pvs.Items)+len(pvcs.Items)+len(attachments.Items) != 0 {
		return fmt.Errorf("k3s hostpath requires a cluster with no PVs, PVCs or VolumeAttachments")
	}

	controller := strings.Split(p.SnapshotController, "/")
	if len(controller) != 2 || controller[0] == "" || controller[1] == "" || p.SnapshotControllerUID == "" {
		return fmt.Errorf("k3s hostpath requires explicit existing snapshot-controller namespace/name and UID")
	}
	deployment, err := e.Kube.Typed.AppsV1().Deployments(controller[0]).Get(ctx, controller[1], metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(deployment.UID) != p.SnapshotControllerUID || deployment.Status.ReadyReplicas < 1 || deployment.Status.ObservedGeneration < deployment.Generation {
		return fmt.Errorf("snapshot-controller identity or readiness does not match")
	}
	upstreamController := false
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if strings.HasPrefix(container.Image, "registry.k8s.io/sig-storage/snapshot-controller:") || strings.HasPrefix(container.Image, "registry.k8s.io/sig-storage/snapshot-controller@sha256:") {
			upstreamController = true
		}
	}
	if !upstreamController {
		return fmt.Errorf("bound snapshot-controller must use the upstream registry.k8s.io/sig-storage/snapshot-controller image")
	}
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return fmt.Errorf("read local machine ID for k3s hostpath binding: %w", err)
	}
	if err := validateK3sMachineID(string(machineID), n.Status.NodeInfo.MachineID); err != nil {
		return err
	}
	for _, dir := range []string{p.KubeletRoot, filepath.Join(p.KubeletRoot, "plugins"), filepath.Join(p.KubeletRoot, "plugins_registry"), filepath.Join(p.KubeletRoot, "pods"), ateomHostDir} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("k3s host directory %s must already exist", dir)
		}
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	for _, dir := range []string{p.KubeletRoot, ateomHostDir} {
		if !sharedMount(string(mounts), dir) {
			return fmt.Errorf("%s must lie on a shared mount before CSI installation", dir)
		}
	}
	for _, dir := range []string{filepath.Join(p.KubeletRoot, "plugins/csi-hostpath"), "/var/lib/csi-hostpath-data", ateomHostDir} {
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("inspect %s: %w", dir, err)
		}
		if len(entries) != 0 {
			return fmt.Errorf("refusing nonempty hostpath directory %s; ate-setup will not erase it", dir)
		}
	}

	objs, err := e.renderK3sHostpath()
	if err != nil {
		return err
	}
	extra, err := kube.DecodeManifestBytes([]byte(csiHostpathControllerService))
	if err != nil {
		return err
	}
	objs = append(objs, extra...)
	class, err := os.ReadFile(e.Cfg.Path("hack/third_party/csi-driver-host-path/examples/csi-storageclass.yaml"))
	if err != nil {
		return err
	}
	extra, err = kube.DecodeManifestBytes(class)
	if err != nil {
		return err
	}
	objs = append(objs, extra...)
	extra, err = kube.DecodeManifestBytes([]byte(k3sCSIDriverConfig))
	if err != nil {
		return err
	}
	objs = append(objs, extra...)
	return e.checkK3sCSIAbsent(ctx, objs)
}

func k3sCSIResource(obj *unstructured.Unstructured) (schema.GroupVersionResource, error) {
	resources := map[string]struct {
		name       string
		namespaced bool
	}{
		"ServiceAccount":      {"serviceaccounts", true},
		"ClusterRole":         {"clusterroles", false},
		"ClusterRoleBinding":  {"clusterrolebindings", false},
		"Role":                {"roles", true},
		"RoleBinding":         {"rolebindings", true},
		"CSIDriver":           {"csidrivers", false},
		"StatefulSet":         {"statefulsets", true},
		"ConfigMap":           {"configmaps", true},
		"Service":             {"services", true},
		"VolumeSnapshotClass": {"volumesnapshotclasses", false},
		"StorageClass":        {"storageclasses", false},
		"CSIDriverConfig":     {"csidriverconfigs", false},
	}
	resource, ok := resources[obj.GetKind()]
	if !ok {
		return schema.GroupVersionResource{}, fmt.Errorf("unsupported k3s hostpath resource kind %s", obj.GetKind())
	}
	if resource.namespaced && obj.GetNamespace() == "" {
		obj.SetNamespace("default")
	}
	gv := obj.GroupVersionKind().GroupVersion()
	return schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: resource.name}, nil
}

func (e *Env) checkK3sCSIAbsent(ctx context.Context, objs []*unstructured.Unstructured) error {
	for _, obj := range objs {
		gvr, err := k3sCSIResource(obj)
		if err != nil {
			return err
		}
		_, err = e.Kube.Dynamic.Resource(gvr).Namespace(obj.GetNamespace()).Get(ctx, obj.GetName(), metav1.GetOptions{})
		if err == nil {
			return fmt.Errorf("refusing existing %s %s/%s; k3s hostpath supports fresh installs only", obj.GetKind(), obj.GetNamespace(), obj.GetName())
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (e *Env) requireK3sResources(ctx context.Context, gv string, names []string) error {
	resources := &metav1.APIResourceList{}
	err := e.Kube.Typed.Discovery().RESTClient().Get().AbsPath("/apis/" + gv).Do(ctx).Into(resources)
	if err != nil {
		return fmt.Errorf("k3s requires enabled API %s: %w", gv, err)
	}
	for _, name := range names {
		found := false
		for _, resource := range resources.APIResources {
			if resource.Name == name {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("k3s requires enabled API %s/%s", gv, name)
		}
	}
	return nil
}

func validateK3sMachineID(local, node string) error {
	local = strings.TrimSpace(local)
	if local == "" || node == "" {
		return fmt.Errorf("k3s hostpath binding requires nonempty local and node machine IDs")
	}
	if local != node {
		return fmt.Errorf("k3s hostpath preflight must run on the bound node: machine IDs do not match")
	}
	return nil
}

func validateK3sNode(n corev1.Node, name, uid string) error {
	if n.Name != name || string(n.UID) != uid {
		return fmt.Errorf("k3s node identity does not match")
	}
	if n.Status.NodeInfo.OperatingSystem != "linux" || !strings.Contains(n.Status.NodeInfo.KubeletVersion, "+k3s") || !strings.HasPrefix(n.Status.NodeInfo.ContainerRuntimeVersion, "containerd://") {
		return fmt.Errorf("k3s requires a Linux node with the k3s kubelet and containerd")
	}
	for _, taint := range n.Spec.Taints {
		if taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute {
			return fmt.Errorf("k3s single-node profile does not tolerate node scheduling taints")
		}
	}
	for _, condition := range n.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue && !n.Spec.Unschedulable {
			return nil
		}
	}
	return fmt.Errorf("k3s node must be Ready and schedulable")
}

func (e *Env) renderK3sHostpath() ([]*unstructured.Unstructured, error) {
	bundle, err := kustomize.Build(e.Cfg.Path("hack/third_party/csi-driver-host-path/deploy"))
	if err != nil {
		return nil, err
	}
	objs, err := kube.DecodeManifestBytes(bundle)
	if err != nil {
		return nil, err
	}
	p := e.Cfg.K3s
	filtered := objs[:0]
	for _, obj := range objs {
		if obj.GetKind() == "Service" && obj.GetName() == "hostpath-service" {
			continue
		}
		filtered = append(filtered, obj)
	}
	objs = filtered
	for _, obj := range objs {
		if _, err := k3sCSIResource(obj); err != nil {
			return nil, err
		}
		if obj.GetKind() != "StatefulSet" {
			continue
		}
		if err := unstructured.SetNestedField(obj.Object, p.Node, "spec", "template", "spec", "nodeName"); err != nil {
			return nil, err
		}
		volumes, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "volumes")
		if err != nil {
			return nil, err
		}
		for _, v := range volumes {
			volume := v.(map[string]interface{})
			hp, ok := volume["hostPath"].(map[string]interface{})
			if !ok {
				continue
			}
			path, _ := hp["path"].(string)
			if strings.HasPrefix(path, "/var/lib/kubelet/") {
				hp["path"] = p.KubeletRoot + strings.TrimPrefix(path, "/var/lib/kubelet")
			}
		}
		containers, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		if err != nil {
			return nil, err
		}
		for _, v := range containers {
			container := v.(map[string]interface{})
			args, _ := container["args"].([]interface{})
			for i, arg := range args {
				value, _ := arg.(string)
				args[i] = strings.ReplaceAll(value, "--kubelet-registration-path=/var/lib/kubelet/", "--kubelet-registration-path="+p.KubeletRoot+"/")
			}
			if container["name"] == "hostpath" {
				mounts := container["volumeMounts"].([]interface{})
				for _, v := range mounts {
					mount := v.(map[string]interface{})
					if path, _ := mount["mountPath"].(string); path == "/var/lib/kubelet/pods" || path == "/var/lib/kubelet/plugins" {
						mount["mountPath"] = p.KubeletRoot + strings.TrimPrefix(path, "/var/lib/kubelet")
					}
				}
				mounts = append(mounts, map[string]interface{}{"name": "ateom-dir", "mountPath": ateomHostDir, "mountPropagation": "Bidirectional"})
				container["volumeMounts"] = mounts
			}
		}
		if obj.GetName() == "csi-hostpathplugin" {
			volumes = append(volumes, map[string]interface{}{"name": "ateom-dir", "hostPath": map[string]interface{}{"path": ateomHostDir, "type": "Directory"}})
		}
		if err := unstructured.SetNestedSlice(obj.Object, volumes, "spec", "template", "spec", "volumes"); err != nil {
			return nil, err
		}
		if err := unstructured.SetNestedSlice(obj.Object, containers, "spec", "template", "spec", "containers"); err != nil {
			return nil, err
		}
	}
	return objs, nil
}

func (e *Env) setupK3sHostpath(ctx context.Context) error {
	objs, err := e.renderK3sHostpath()
	if err != nil {
		return err
	}
	if err := e.createK3sCSIManifest(ctx, []byte(csiHostpathControllerService)); err != nil {
		return err
	}
	if err := e.createK3sCSI(ctx, objs); err != nil {
		return err
	}
	class, err := os.ReadFile(e.Cfg.Path("hack/third_party/csi-driver-host-path/examples/csi-storageclass.yaml"))
	if err != nil {
		return err
	}
	if err := e.createK3sCSIManifest(ctx, class); err != nil {
		return err
	}
	for _, name := range []string{"csi-hostpathplugin", "csi-hostpath-socat"} {
		if err := e.Kube.RolloutStatus(ctx, kube.KindStatefulSet, "default", name, e.Cfg.WaitTimeout(BootstrapTimeout)); err != nil {
			return err
		}
	}
	return e.createK3sCSIManifest(ctx, []byte(k3sCSIDriverConfig))
}

const k3sCSIDriverConfig = `apiVersion: ate.dev/v1alpha1
kind: CSIDriverConfig
metadata:
  name: hostpath.csi.k8s.io
spec:
  driverName: hostpath.csi.k8s.io
  controllerEndpoint: tcp://csi-hostpath-controller.default.svc.cluster.local:50051
  nodeSocketOverride: unix:///var/lib/kubelet/plugins/csi-hostpath/csi.sock
  tls:
    enabled: true
    usePodIdentity: true
    serverName: csi-hostpath-controller.default.svc
`

func (e *Env) createK3sCSIManifest(ctx context.Context, manifest []byte) error {
	objs, err := kube.DecodeManifestBytes(manifest)
	if err != nil {
		return err
	}
	return e.createK3sCSI(ctx, objs)
}

func (e *Env) createK3sCSI(ctx context.Context, objs []*unstructured.Unstructured) error {
	for _, obj := range objs {
		gvr, err := k3sCSIResource(obj)
		if err != nil {
			return err
		}
		if _, err := e.Kube.Dynamic.Resource(gvr).Namespace(obj.GetNamespace()).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create %s %s/%s; retain prior created resources for reviewed recovery: %w", obj.GetKind(), obj.GetNamespace(), obj.GetName(), err)
		}
	}
	return nil
}

func (e *Env) configureK3sManifest(manifest []byte) ([]byte, error) {
	if e.Cfg.K3s == nil {
		return manifest, nil
	}
	objs, err := kube.DecodeManifestBytes(manifest)
	if err != nil {
		return nil, err
	}
	p := e.Cfg.K3s
	for _, obj := range objs {
		if obj.GetKind() != "DaemonSet" && obj.GetKind() != "Deployment" {
			continue
		}
		containers, found, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		for _, v := range containers {
			container := v.(map[string]interface{})
			if container["name"] != "atelet" && container["name"] != "ate-api-server" {
				continue
			}
			if e.s3CA != nil && isK3sS3CATarget(obj, container) {
				if obj.GetNamespace() != e.Namespace() {
					return nil, fmt.Errorf("%s/%s must be in namespace %s for the S3 CA projection", obj.GetKind(), obj.GetName(), e.Namespace())
				}
				if err := addK3sS3CAProjection(obj, container, e.s3CA); err != nil {
					return nil, fmt.Errorf("%s/%s: %w", obj.GetKind(), obj.GetName(), err)
				}
			}
			env, _ := container["env"].([]interface{})
			for _, pair := range [][2]string{{"ATE_STORAGE_BACKEND", "s3"}, {"AWS_ENDPOINT_URL", p.S3Endpoint}, {"AWS_REGION", p.S3Region}, {"AWS_S3_USE_PATH_STYLE", "true"}, {"AWS_EC2_METADATA_DISABLED", "true"}} {
				env = setK3sEnv(env, map[string]interface{}{"name": pair[0], "value": pair[1]})
			}
			for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
				env = setK3sEnv(env, map[string]interface{}{"name": key, "valueFrom": map[string]interface{}{"secretKeyRef": map[string]interface{}{"name": p.S3Secret, "key": key}}})
			}
			container["env"] = env
		}
		if obj.GetLabels()["app"] == "atelet" || strings.HasPrefix(obj.GetName(), "atelet-") {
			if err := unstructured.SetNestedField(obj.Object, p.Node, "spec", "template", "spec", "nodeName"); err != nil {
				return nil, err
			}
			volumes, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "volumes")
			if err != nil {
				return nil, err
			}
			for _, v := range volumes {
				volume := v.(map[string]interface{})
				hp, ok := volume["hostPath"].(map[string]interface{})
				if !ok {
					continue
				}
				path, _ := hp["path"].(string)
				if strings.HasPrefix(path, "/var/lib/kubelet/") {
					hp["path"] = p.KubeletRoot + strings.TrimPrefix(path, "/var/lib/kubelet")
				}
			}
			if err := unstructured.SetNestedSlice(obj.Object, volumes, "spec", "template", "spec", "volumes"); err != nil {
				return nil, err
			}
		}
		if err := unstructured.SetNestedSlice(obj.Object, containers, "spec", "template", "spec", "containers"); err != nil {
			return nil, err
		}
	}
	var out bytes.Buffer
	for _, obj := range objs {
		data, err := json.Marshal(obj.Object)
		if err != nil {
			return nil, err
		}
		out.Write(data)
		out.WriteString("\n---\n")
	}
	return out.Bytes(), nil
}

func setK3sEnv(env []interface{}, value map[string]interface{}) []interface{} {
	for i, v := range env {
		if v.(map[string]interface{})["name"] == value["name"] {
			env[i] = value
			return env
		}
	}
	return append(env, value)
}
