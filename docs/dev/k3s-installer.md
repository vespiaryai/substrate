# Native single-node k3s installer profile

`ate-setup --k3s` targets an existing Linux k3s node with containerd. The profile supports the `size0` control plane, Envoy, and either no CSI driver or the upstream single-node Hostpath test driver. Kind behavior stays unchanged. Bundled PostgreSQL alone reuses the upstream small Kind sizing overlay. It requests 250m CPU and 1 GiB memory, limits itself to 2 CPU and 2 GiB memory, and claims 1 GiB of storage. Its certificate projections remain unchanged.

The profile requires explicit kubeconfig, context, node name, node UID, kube-system UID, and kubelet root. It skips `.ate-dev-env.sh` and rejects GCP coordinates, Cloud SQL, other size profiles, and control-plane cordon options. The common CLI boundary reads cluster identity, node readiness, and certificate APIs before any step can write.

## Required inputs

| Flag | Required value |
| --- | --- |
| `--kubeconfig` | One explicit kubeconfig file |
| `--context` | The intended context |
| `--k3s-node` | The single node name |
| `--k3s-node-uid` | The inspected node UID |
| `--k3s-system-uid` | The inspected kube-system namespace UID |
| `--k3s-kubelet-root` | The inspected clean absolute kubelet root |
| `--k3s-s3-endpoint` | An existing S3-compatible HTTPS endpoint |
| `--k3s-s3-region` | The endpoint's region |
| `--k3s-s3-secret` | An existing ate-system Secret with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` |
| `--k3s-s3-ca-file` | Optional absolute path to a public PEM certificate bundle for the S3 endpoint |
| `--storage-bucket-name` | An existing snapshot bucket |

The installer references the snapshot Secret without reading or creating it. Both ate-api-server and atelet use the same explicit S3 settings. No GCS credentials, local RustFS demo credentials, or plaintext storage proxy enter this profile. Without a CA file, the HTTPS endpoint must have a certificate trusted by the shipped images. Private registry credentials still need an explicit supported configuration. The profile removes GKE's host credential-provider mounts without installing a replacement.

With a CA file, the installer validates one public PEM snapshot before cluster writes and creates `ate-system/ate-s3-ca`. Both clients mount the ConfigMap read-only and set `AWS_CA_BUNDLE` to its certificate file. The bundle replaces their default AWS root pool, so include every root those clients need. The host file must contain certificates only, never a private key or credentials. A changed bundle requires a reviewed full `deploy ate-system` run to update both pod templates. Standalone component deploys accept unchanged bytes but refuse a changed shared bundle. A full deploy has other setup effects and is not an automatic rotation command.

The API server must expose `certificates.k8s.io/v1beta1` PodCertificateRequests and ClusterTrustBundles. The kubelet must enable pod certificate and trust bundle projections. API discovery proves exposure, not successful certificate issuance or kubelet projection. Live qualification must prove both. The installer does not alter k3s feature gates or configuration.

## Hostpath prerequisites

Hostpath is a development test driver, not a production storage choice. This profile requires an otherwise empty storage cluster. Any PV, PVC, or VolumeAttachment causes preflight to fail. NFS and `both` are unsupported.

The profile requires an existing upstream snapshot-controller Deployment. `--k3s-snapshot-controller` names its namespace and Deployment as `namespace/name`. `--k3s-snapshot-controller-uid` binds its UID. Preflight checks that UID, a Ready replica, observed generation, and the upstream registry image. It also requires all three `snapshot.storage.k8s.io/v1` APIs. The installer does not install the snapshot controller or its CRDs.

Hostpath preflight automatically binds the local `/etc/machine-id` to the machine ID reported by the UID-bound node. Both must be nonempty and match. The node name may differ from the local hostname; no extra approval flag is needed. The kubelet root, its `pods`, `plugins`, and `plugins_registry` directories, and `/var/lib/ate` must already exist. The kubelet root and `/var/lib/ate` must lie on shared mounts. `/var/lib/ate`, the Hostpath plugin socket directory, and `/var/lib/csi-hostpath-data` must be empty or absent where creation is supported. Existing rendered CSI resources, including CSIDriverConfig, cause preflight to fail. An absent CSIDriverConfig API before bootstrap is allowed. The installer never deletes resources, unmounts disks, runs Docker commands, or erases host directories on this path.

Before creation, the installer renders both CSI StatefulSets pinned to the bound node. HostPaths and the registrar's kubelet socket argument use the explicit native kubelet root. The Hostpath driver mounts its pods and plugins directories at the same native absolute paths because NodePublish receives native kubelet paths. Other containers keep their upstream aliases. The CSIDriverConfig uses the socket alias inside atelet, `/var/lib/kubelet/plugins/csi-hostpath/csi.sock`. The Hostpath driver mounts `/var/lib/ate` with bidirectional propagation. The existing Envoy controller proxy keeps mutual TLS and pod identity checks. The native bundle removes the testing Service that opens a NodePort. The controller uses only its internal ClusterIP Service.

The installer creates the internal controller Service first, then the vendored driver resources and StorageClass. It creates CSIDriverConfig only after the driver rolls out. Every native CSI write uses CREATE. If another installer creates a resource after preflight, installation stops on AlreadyExists without adoption or forced replacement. A partial failure retains resources already created. Record their exact names and UIDs for reviewed recovery. The installer does not roll them back or delete them.

## Execution boundaries

The installer performs the selected install after preflight succeeds. It is not a dry-run command. This patch does not apply feature gates, restart k3s, create external storage credentials, or install storage prerequisites during preparation.

A later execution review must approve the exact certificate gates and any k3s restart, snapshot APIs and controller, credential Secret, host directories and mount settings, privileged CSI containers, and RBAC. The reviewer also needs the resolved image digests and final rendered resources. Passing preflight does not grant that approval.

The profile does not implement the Vespiary trial's aggregate 6 CPU, 8 GiB, 20 GiB disk, or independent 15-minute shutdown limits. Those controls must cover every namespace and host process before an install can qualify as a bounded trial. Existing driver manifests include privileged containers and do not supply those aggregate limits.

The upstream default SandboxConfig still pins the 2026-09-02 gVisor nightly asset. Vespiary Goal330 requires release-20260831.0. This installer patch does not change that asset or establish profile compatibility. A later trial must select and review the exact compatible asset and effective profile.

The full configuration test suite, focused k3s and PostgreSQL tests, actual installer CLI help, formatting, and manifest rendering pass locally. The tests run under a shared validation lock with verified 6 CPU, 8 GiB, zero-swap cgroup limits and a 15-minute systemd deadline. Whole-repository `make verify` and real deployment checks remain pending. No runtime qualification is implied.
