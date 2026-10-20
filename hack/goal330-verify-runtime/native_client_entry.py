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

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys


def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise RuntimeError("client input exceeds bound or is not regular")
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise RuntimeError("client input exceeds bound")
    return body


def client_argv(kind, persistent, runtime):
    if kind == "docker":
        return ["/usr/bin/docker", "--config", str(persistent / "docker-config"), "--host",
                f"unix://{runtime}/docker.sock", "info", "--format", "{{json .}}"]
    if kind == "rootlesskit":
        return ["/usr/bin/curl", "--disable", "--silent", "--show-error", "--fail", "--proxy", "",
                "--noproxy", "*", "--proto", "=http", "--http1.1", "--request", "GET",
                "--retry", "0", "--max-redirs", "0", "--max-time", "5", "--max-filesize", "65536",
                "--unix-socket", str(runtime / "rootlesskit/api.sock"), "--output",
                str(persistent / "rootlesskit-info.json"), "--write-out", "%{http_code}",
                "http://rootlesskit/v1/info"]
    raise RuntimeError("client outside fixed native observation scope")


def read_witness(path):
    body = read_bounded(path, 16384)
    value = json.loads(body)
    if (any(type(value.get(key)) is not int or value[key] <= 0
            for key in ("pid", "starttime", "ppid", "pgrp"))
            or not re.fullmatch(r"[0-9a-f]{32}", value.get("invocation", ""))
            or not value.get("boot") or not value.get("cgroup") or not value.get("argv")):
        raise RuntimeError("missing positive pre-exec native identity")
    return value


def client_entry(kind, nonce):
    if not re.fullmatch(r"[0-9a-f]{32}", nonce) or nonce in (
        "b7a6306f20fabfaab02a29eaecf04531", "18ec13b3d43234b8ab4f79fbc49e0c1d"
    ):
        raise RuntimeError("client identity is not a fresh root assignment")
    persistent = Path(f"/home/zack/.local/share/vesverify{nonce}")
    runtime = Path(f"/run/user/1000/vesverify{nonce}")
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    body = read_bounded(persistent / f"{kind}-plan.json", 16384)
    plan = json.loads(body)
    boot = read_bounded(Path("/proc/sys/kernel/random/boot_id"), 65536).decode().strip()
    before = read_bounded(Path("/proc/self/stat"), 65536).decode().rsplit(")", 1)[1].split()
    group = read_bounded(Path("/proc/self/cgroup"), 65536).decode().strip()
    invocation = os.environ.get("INVOCATION_ID", "")
    entry = str(Path(__file__).resolve())
    if (not sys.flags.isolated or not sys.flags.no_site or not group.startswith("0::")
            or group[3:] != plan["cgroup"] or boot != plan["boot"]
            or not re.fullmatch(r"[0-9a-f]{32}", invocation) or not int(invocation, 16)
            or plan["entry"] != {entry: hashlib.sha256(read_bounded(Path(entry), 1048576)).hexdigest()}):
        raise RuntimeError("client pre-exec native placement/input mismatch")
    argv = client_argv(kind, persistent, runtime)
    witness = {"boot": boot, "unit": plan["unit"], "invocation": invocation, "cgroup": group[3:],
               "pid": os.getpid(), "starttime": int(before[19]), "ppid": int(before[1]),
               "pgrp": int(before[2]), "argv": argv}
    path = persistent / f"{kind}-entry.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(witness, sort_keys=True).encode() + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(persistent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    after = read_bounded(Path("/proc/self/stat"), 65536).decode().rsplit(")", 1)[1].split()
    if before[19] != after[19] or read_bounded(Path("/proc/self/cgroup"), 65536).decode().strip() != group:
        raise RuntimeError("client changed identity before exec")
    os.execve(argv[0], argv, {"PATH": "/usr/bin:/bin", "HOME": str(persistent / "home"),
                            "DOCKER_CONFIG": str(persistent / "docker-config"), "LC_ALL": "C", "LANG": "C"})


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("expected one fixed client kind and a separately assigned nonce")
    client_entry(sys.argv[1], sys.argv[2])
