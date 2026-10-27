# ate-setup

Installs and tears down Agent Substrate on a Kubernetes cluster.

```
go run ./cmd/ate-setup [global flags] <command> [flags]
make build-ate-setup    # builds bin/ate-setup
```

`ate-setup` is the installer. `hack/install-ate.sh` is a shim over it, kept so
that existing command lines and CI jobs keep working; it holds no install logic
of its own.

## Installing a release

By default every image is built from the checkout with `ko`, which is what a
developer wants and what the shell installer always did. To install published
images instead, name the registry they were pushed to:

```
ate-setup deploy ate-system \
  --credential-provider='{"name":"k8s.io"}' \
  --image-repo registry.example.com/substrate \
  --image-tag v0.0.0
```

Nothing is built and no registry is pushed to; the manifests still come from the
checkout. Each reference is pinned to the digest its tag names, so the registry
has to be readable from here as well as from the cluster.

- [`commands.md`](commands.md) — every command with its `hack/install-ate.sh`
  equivalent.
- [`differences.md`](differences.md) — where the Go port deliberately behaves
  differently from the shell scripts it replaced, and what was reproduced
  exactly.
- [`cli-diff.md`](cli-diff.md) — what a `hack/install-ate.sh` user can observe
  after the switch.

## Staging k3s S3 trust

Use `rotate s3 inspect` to capture the current ConfigMap UID, CA hash, resource
version, client template hashes, and Pod UIDs. Save its JSON output before
changing the cluster. The configuration must still name the installed old S3
endpoint.

```
ate-setup --config /absolute/install.yaml rotate s3 inspect \
  --client Deployment/ate-api-server=API_UID \
  --client DaemonSet/ATELET_NAME=ATELET_UID \
  > /absolute/expected.json
ate-setup --config /absolute/install.yaml rotate s3 trust \
  --expected /absolute/expected.json \
  --ca-file /absolute/old-and-new-public-roots.pem \
  --rotation-receipt /absolute/new-rotation-receipt.json
```

Pass every installed `app=atelet` DaemonSet to `inspect`, after verifying each
name and UID independently. Recheck the live UIDs before running `trust`.
The trust command accepts only a bundle of current public certificates that
contains the installed old root and at least one additional CA with certificate
signing usage. It checks the
installer owner, exact old CA hash and UID, ConfigMap resource version, and
every API server and atelet workload UID, resource version, and Pod template.
It updates the CA ConfigMap and the client Pod templates with Kubernetes
resource-version checks, then waits for ready replacement Pods owned by the
Deployment's ReplicaSet or the DaemonSet, with new UIDs.
It writes a separate receipt without replacing the historical install record.

An update error stops the command after a fresh read of the CA and client
templates. The error names the observed old, target, or partial state. Inspect
those live resources before retrying with the original expected JSON and an
unused receipt path.
After success, prove a signed S3 read through both real clients against the old
endpoint before switching endpoints. This command does not copy S3 data or
change the endpoint.
