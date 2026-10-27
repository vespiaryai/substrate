#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Render and apply only the maintained native egress gateway."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "manifests/ate-install/atenet-egress.yaml"
POLICY = ROOT / "deploy/k8s/local/goal330-native-egress-networkpolicy.yaml"
OBJECTS = (
    "serviceaccount/atenet-egress",
    "configmap/atenet-egress",
    "deployment/atenet-egress",
    "service/atenet-egress",
    "secret/egress-mitm-ca-pool",
    "networkpolicy/goal330-native-egress-gateway-traffic",
    "networkpolicy/goal330-native-api-from-egress",
)
NATIVE = "ko://github.com/agent-substrate/substrate/cmd/atenet"
ENVOY = "${ENVOY_DATAPLANE_IMAGE}"
MARKER = "        #ATE_EGRESS_INJECT_FLAGS -- Don't modify this line.\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def render(native_image, envoy_image):
    raw = SOURCE.read_text()
    for token, count in ((NATIVE, 2), (ENVOY, 1), (MARKER, 1)):
        if raw.count(token) != count:
            raise ValueError(f"maintained egress marker count changed: {token!r}")
    return raw.replace(NATIVE, native_image).replace(ENVOY, envoy_image).replace(MARKER, "").encode()


def metadata(namespace, resource, context):
    result = subprocess.run(
        ["kubectl", "--context=" + context, "-n", namespace, "get", resource, "-o", "json"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        if "(NotFound)" in result.stderr:
            return None
        raise RuntimeError(f"reading {resource} failed: {result.stderr.strip()}")
    obj = json.loads(result.stdout)
    return {key: obj["metadata"][key] for key in ("uid", "resourceVersion")}


def snapshot(namespace, context):
    return {resource: metadata(namespace, resource, context) for resource in OBJECTS}


def binding():
    context = subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
    if not context:
        raise RuntimeError("required cluster context is absent")
    result = {
        "context": context,
        "kube_system": metadata("kube-system", "namespace/kube-system", context),
        "ate_system": metadata("ate-system", "namespace/ate-system", context),
        "worker_namespace": metadata("ate-demo-sandbox", "namespace/ate-demo-sandbox", context),
        "api_deployment": metadata("ate-system", "deployment/ate-api-server", context),
    }
    if not result["context"] or any(result[name] is None for name in ("kube_system", "ate_system", "worker_namespace", "api_deployment")):
        raise RuntimeError("required cluster binding is absent")
    return result


def save(path, value):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".operation-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def invoke(argv, record):
    record["next_command"] = argv
    record["state"] = "attempted_write"
    record.setdefault("attempts", []).append(argv)
    save(record["receipt"], {k: v for k, v in record.items() if k != "receipt"})
    result = subprocess.run(argv, cwd=ROOT, check=False)
    if result.returncode:
        record["exit_code"] = result.returncode
        raise RuntimeError(f"command failed or write outcome uncertain: {argv[0]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "apply"))
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--atenet-image", required=True)
    parser.add_argument("--envoy-image", required=True)
    parser.add_argument("--receipt-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.namespace != "ate-system":
        parser.error("the maintained gateway addresses ate-system and requires that namespace")
    for image in (args.atenet_image, args.envoy_image):
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
            parser.error("both image references must carry a full sha256 digest")
    os.umask(0o077)
    directory = args.receipt_dir.resolve()
    if args.phase == "prepare":
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    elif not directory.is_dir() or directory.stat().st_mode & 0o077:
        parser.error("receipt directory is absent or accessible by another user")
    candidate = directory / "atenet-egress.yaml"
    receipt = directory / "operation.json"
    rendered = render(args.atenet_image, args.envoy_image)
    policy = POLICY.read_bytes()
    if args.phase == "prepare":
        candidate.write_bytes(rendered)
        candidate.chmod(0o600)
        cluster = binding()
        before = snapshot(args.namespace, cluster["context"])
        if any(before[name] is not None for name in OBJECTS if name != "secret/egress-mitm-ca-pool"):
            raise RuntimeError("a create-only target already exists")
        record = {
            "state": "prepared_no_write",
            "namespace": args.namespace,
            "atenet_image": args.atenet_image,
            "envoy_image": args.envoy_image,
            "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_sha256": digest(SOURCE.read_bytes()),
            "manifest_sha256": digest(rendered),
            "policy_sha256": digest(policy),
            "binding": cluster,
            "before": before,
        }
        save(receipt, record)
        print(json.dumps({"manifest": str(candidate), "receipt": str(receipt), "manifest_sha256": record["manifest_sha256"]}))
        return
    record = json.loads(receipt.read_text())
    if record["state"] != "prepared_no_write":
        raise RuntimeError("receipt has an attempted write; reconcile it before another operation")
    if (record["namespace"], record["atenet_image"], record["envoy_image"]) != (args.namespace, args.atenet_image, args.envoy_image):
        raise RuntimeError("operation arguments changed after preparation")
    if (digest(SOURCE.read_bytes()), digest(candidate.read_bytes()), digest(policy)) != (
        record["source_sha256"], record["manifest_sha256"], record["policy_sha256"]
    ) or candidate.read_bytes() != rendered:
        raise RuntimeError("reviewed source, manifest, or policy changed")
    context = record["binding"]["context"]
    if any(record["before"][name] is not None for name in OBJECTS if name != "secret/egress-mitm-ca-pool"):
        raise RuntimeError("a create-only target existed at preparation")
    if snapshot(args.namespace, context) != record["before"]:
        raise RuntimeError("resource UID or version changed after preparation")
    if binding() != record["binding"]:
        raise RuntimeError("cluster, namespace, or API binding changed after preparation")
    record["receipt"] = receipt
    try:
        invoke(["mise", "exec", "--", "go", "run", "./cmd/ate-setup", "--no-dev-env", "--namespace=" + args.namespace, "--context=" + context, "create", "egress-mitm-ca-pool"], record)
        after_ca = snapshot(args.namespace, context)
        if any(after_ca[name] is not None for name in OBJECTS if name != "secret/egress-mitm-ca-pool"):
            raise RuntimeError("a create-only target appeared after CA creation; reconcile before apply")
        if after_ca["secret/egress-mitm-ca-pool"] is None:
            raise RuntimeError("CA helper returned without a Secret; reconcile before apply")
        invoke(["kubectl", "--context=" + context, "-n", args.namespace, "create", "-f", str(candidate)], record)
        invoke(["kubectl", "--context=" + context, "-n", args.namespace, "create", "-f", str(POLICY)], record)
        after = snapshot(args.namespace, context)
        if any(after[name] is None for name in OBJECTS):
            raise RuntimeError("created resources are absent at readback; reconcile before retry")
        record["after"] = after
        record["state"] = "applied_readback"
        record.pop("next_command", None)
        save(receipt, {k: v for k, v in record.items() if k != "receipt"})
    except BaseException:
        if record["state"] != "applied_readback":
            record["state"] = "uncertain_write"
            save(receipt, {k: v for k, v in record.items() if k != "receipt"})
        raise


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
