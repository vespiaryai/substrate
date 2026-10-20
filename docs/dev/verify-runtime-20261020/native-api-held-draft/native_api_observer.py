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

import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import tomllib

import dbus

from systemd_job import owned_job, user_bus


BASE = "b1a13f74503326f5ff477e5516a35159ea11eeae"
BUS = "unix:path=/run/user/1000/bus"
MANAGER = "org.freedesktop.systemd1.Manager"
UNIT = "org.freedesktop.systemd1.Unit"
SERVICE = "org.freedesktop.systemd1.Service"
CGROUP = Path("/sys/fs/cgroup")
PROC = Path("/proc")
REVIEWS = Path("/home/zack/.codex/orchestrate/vespiary-goal330/reviews")
CONTRACT = "native owned-service closure under no external namespace-reference acquisition"
MAX_RESPONSE = 65536


def present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def strict_json(body):
    if len(body) > MAX_RESPONSE:
        raise RuntimeError("oversize native response")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError(f"nonfinite JSON number {value}")

    return json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)


def digest_map(paths):
    return {str(path): hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths}


def frozen_inputs():
    manifest = Path(__file__).resolve().parents[2] / "docs/dev/verify-runtime-20261020/native-api-inputs.sha256"
    expected = {}
    for line in manifest.read_text().splitlines():
        digest, name = line.split("  ", 1)
        path = Path(name)
        if not path.is_absolute():
            path = manifest.parents[3] / path
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or str(path) in expected:
            raise RuntimeError("invalid immutable input map")
        expected[str(path)] = digest
    if digest_map(expected) != expected:
        raise RuntimeError("frozen source/native/oracle input mismatch")
    return {**expected, **digest_map((manifest,))}


def append_receipt(path, value):
    body = json.dumps(value, sort_keys=True, default=lambda obj: obj.hex()
                      if isinstance(obj, bytes) else dataclasses.asdict(obj)).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def cgroup_path(value):
    if not value.startswith("/") or ".." in Path(value).parts or value == "/":
        raise RuntimeError("invalid owned cgroup path")
    path = CGROUP / value.lstrip("/")
    if path.resolve() != path:
        raise RuntimeError("cgroup path resolves elsewhere")
    return path


def bounded_parent(value):
    leaf = cgroup_path(value)
    rows = []
    for path in (leaf, *leaf.parents):
        if path == CGROUP.parent:
            break
        rows.append({"path": str(path), **{
            key: (path / key).read_text().strip() if present(path / key) else None
            for key in ("cpu.max", "memory.max", "memory.swap.max", "pids.max",
                        "cgroup.controllers", "cgroup.subtree_control")
        }})
    exact = rows[0]
    quota, period = exact["cpu.max"].split()
    if (quota == "max" or not 0 < int(quota) <= 2 * int(period)
            or exact["memory.max"] == "max" or not 0 < int(exact["memory.max"]) <= 4294967296
            or exact["memory.swap.max"] != "0" or exact["pids.max"] == "max"
            or not 0 < int(exact["pids.max"]) <= 512
            or not {"cpu", "memory", "pids"} <= set(exact["cgroup.controllers"].split())):
        raise RuntimeError("actual pre-birth bounds exceed allocation")
    return rows


def host_state():
    enforce = Path("/sys/fs/selinux/enforce").read_text().strip()
    if enforce != "1":
        raise RuntimeError("host SELinux is not Enforcing")
    files = [Path("/proc/sys/net/ipv4/ip_forward"),
             Path("/proc/sys/net/ipv6/conf/all/forwarding"), Path("/etc/subuid"),
             Path("/etc/subgid"), Path("/etc/docker/daemon.json"),
             Path("/usr/lib/systemd/system/docker.service"),
             Path("/usr/lib/systemd/user/docker.service")]
    listeners = {}
    for name in ("tcp", "tcp6"):
        rows = Path(f"/proc/self/net/{name}").read_text().splitlines()[1:]
        listeners[name] = sorted(row.split()[1] for row in rows if row.split()[3] == "0A")
    return {"enforce": enforce, "run_label": os.getxattr("/run", "security.selinux").hex(),
            "listeners": listeners,
            "files": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                      if present(path) else None for path in files}}


@dataclasses.dataclass(frozen=True)
class NativeIdentity:
    boot: str
    unit: str
    invocation: bytes
    cgroup: str
    job: str
    pid: int = 0
    starttime: int = 0
    ppid: int = 0
    pgrp: int = 0
    argv: tuple[str, ...] = ()


def process_identity(pid, placement):
    root = PROC / str(pid)
    boot = (PROC / "sys/kernel/random/boot_id").read_text().strip()
    before = (root / "stat").read_text().rsplit(")", 1)[1].split()
    group = (root / "cgroup").read_text().strip()
    if not group.startswith("0::"):
        raise RuntimeError("not unified cgroup v2")
    group = group[3:]
    if group != placement.cgroup and not group.startswith(placement.cgroup + "/"):
        raise RuntimeError("observed process escaped native placement")
    result = dataclasses.replace(
        placement, pid=pid, starttime=int(before[19]), ppid=int(before[1]),
        pgrp=int(before[2]), cgroup=group,
        argv=tuple(x.decode("utf-8") for x in (root / "cmdline").read_bytes().split(b"\0") if x),
    )
    after = (root / "stat").read_text().rsplit(")", 1)[1].split()
    if (before[19] != after[19] or boot != placement.boot
            or boot != (PROC / "sys/kernel/random/boot_id").read_text().strip()
            or (root / "cgroup").read_text().strip() != "0::" + group):
        raise RuntimeError("boot, PID or cgroup changed during observation")
    return result


def properties(bus, name, interface):
    manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1"), MANAGER)
    path = manager.GetUnit(name, timeout=5)
    obj = bus.get_object("org.freedesktop.systemd1", path)
    return dbus.Interface(obj, "org.freedesktop.DBus.Properties").GetAll(interface, timeout=5)


@dataclasses.dataclass(frozen=True)
class Attempt:
    nonce: str

    def __post_init__(self):
        if (not isinstance(self.nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", self.nonce)
                or self.nonce in ("b7a6306f20fabfaab02a29eaecf04531",
                                  "18ec13b3d43234b8ab4f79fbc49e0c1d")):
            raise RuntimeError("root must separately assign an unused native observation identity")

    @property
    def p(self):
        return Path(f"/home/zack/.local/share/vesverify{self.nonce}")

    @property
    def r(self):
        return Path(f"/run/user/1000/vesverify{self.nonce}")

    @property
    def units(self):
        prefix = f"vesverify{self.nonce}"
        return (prefix + ".slice", prefix + "-daemon.service", prefix + "-info.service",
                prefix + "-api.service")

    @property
    def receipt(self):
        return REVIEWS / f"daemon-only-pending-{self.nonce}.json"

    @property
    def uri(self):
        return f"unix://{self.r}/docker.sock"

    @property
    def sockets(self):
        return (self.r / "docker.sock", self.r / "rootlesskit/api.sock",
                self.r / "exec/containerd/containerd.sock",
                self.r / "exec/containerd/containerd-debug.sock")

    def daemon_config(self):
        return {"data-root": str(self.p / "data"), "exec-root": str(self.r / "exec"),
                "pidfile": str(self.r / "docker.pid"), "hosts": [self.uri],
                "exec-opts": ["native.cgroupdriver=systemd"], "cgroup-parent": self.units[0],
                "default-cgroupns-mode": "private", "ip": "127.0.0.1",
                "default-network-opts": {
                    "bridge": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"}},
                "features": {"containerd-snapshotter": True, "embedded-containerd": False},
                "max-concurrent-downloads": 1, "max-download-attempts": 1,
                "shutdown-timeout": 10}

    def daemon_argv(self):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.p / "home"),
               "XDG_CONFIG_HOME": str(self.p / "config"),
               "XDG_DATA_HOME": str(self.p / "xdgdata"), "XDG_CACHE_HOME": str(self.p / "cache"),
               "XDG_RUNTIME_DIR": str(self.r / "xdg"), "TMPDIR": str(self.p / "tmp"),
               "DBUS_SESSION_BUS_ADDRESS": BUS,
               "DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": str(self.r / "rootlesskit"),
               "CONTAINERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": str(self.r / "no-standalone-containerd"),
               "DOCKERD_ROOTLESS_ROOTLESSKIT_NET": "pasta",
               "DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER": "implicit",
               "DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS": "true",
               "DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK": "true"}
        return ["/usr/bin/env", "-i", *[f"{key}={value}" for key, value in env.items()],
                "/usr/bin/dockerd-rootless.sh", f"--config-file={self.p}/daemon.json", "--group=0"]

    def api_argv(self):
        return ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", f"HOME={self.p}/home",
                "/usr/bin/curl", "--disable", "--silent", "--show-error", "--fail",
                "--proxy", "", "--noproxy", "*", "--proto", "=http", "--http1.1",
                "--request", "GET", "--retry", "0", "--max-redirs", "0", "--max-time", "5",
                "--max-filesize", str(MAX_RESPONSE), "--unix-socket",
                str(self.r / "rootlesskit/api.sock"), "--output", str(self.p / "rootlesskit-info.json"),
                "--write-out", "%{http_code}", "http://rootlesskit/v1/info"]

    def unit_properties(self, name):
        if name not in self.units:
            raise RuntimeError("unit outside prospective native scope")
        values = [("Description", dbus.String(f"goal330-native-api {self.nonce}")),
                  ("StopWhenUnneeded", dbus.Boolean(False))]
        if name == self.units[0]:
            values += [("CPUQuotaPerSecUSec", dbus.UInt64(2000000)),
                       ("MemoryMax", dbus.UInt64(4294967296)),
                       ("MemorySwapMax", dbus.UInt64(0)), ("TasksMax", dbus.UInt64(512))]
        else:
            daemon = name == self.units[1]
            if daemon:
                argv = self.daemon_argv()
            elif name == self.units[2]:
                argv = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", f"HOME={self.p}/home",
                        f"DOCKER_CONFIG={self.p}/docker-config", "/usr/bin/docker", "--config",
                        str(self.p / "docker-config"), "--host", self.uri,
                        "info", "--format", "{{json .}}"]
            else:
                argv = self.api_argv()
            values += [("Type", dbus.String("exec" if daemon else "oneshot")),
                       ("Slice", dbus.String(self.units[0])), ("Delegate", dbus.Boolean(daemon)),
                       ("Restart", dbus.String("no")), ("KillMode", dbus.String("control-group")),
                       ("SendSIGKILL", dbus.Boolean(True)),
                       ("TimeoutStartUSec", dbus.UInt64(15000000 if daemon else 10000000)),
                       ("TimeoutStopUSec", dbus.UInt64(15000000 if daemon else 5000000)),
                       ("ExecStart", dbus.Array([(argv[0], argv, False)], signature="(sasb)"))]
            if daemon:
                values += [("RuntimeMaxUSec", dbus.UInt64(180000000)),
                           ("RuntimeRandomizedExtraUSec", dbus.UInt64(0))]
            else:
                stem = "info" if name == self.units[2] else "rootlesskit-status"
                values += [("RemainAfterExit", dbus.Boolean(True)),
                           ("StandardOutputFile", dbus.String(str(self.p / f"{stem}.json"))),
                           ("StandardErrorFile", dbus.String(str(self.p / f"{stem}.stderr")))]
        return dbus.Array(values, signature="(sv)")

    def identity(self, name, job):
        bus = user_bus()
        try:
            unit = properties(bus, name, UNIT)
            controls = properties(bus, name, "org.freedesktop.systemd1.Slice"
                                  if name == self.units[0] else SERVICE)
        finally:
            bus.close()
        boot = (PROC / "sys/kernel/random/boot_id").read_text().strip()
        invocation, group = bytes(unit["InvocationID"]), str(controls["ControlGroup"])
        if (not unit["Transient"] or unit["ActiveState"] != "active"
                or unit["Description"] != f"goal330-native-api {self.nonce}"
                or len(invocation) != 16 or not any(invocation)):
            raise RuntimeError("native unit identity mismatch")
        if name == self.units[0]:
            if unit["StopWhenUnneeded"]:
                raise RuntimeError("parent can disappear before postflight")
            cgroup_path(group)
        else:
            daemon = name == self.units[1]
            if (controls["Slice"] != self.units[0] or controls["KillMode"] != "control-group"
                    or controls["Restart"] != "no" or bool(controls["Delegate"]) != daemon
                    or controls["Type"] != ("exec" if daemon else "oneshot")
                    or not controls["SendSIGKILL"]
                    or int(controls["TimeoutStartUSec"]) != (15000000 if daemon else 10000000)
                    or int(controls["TimeoutStopUSec"]) != (15000000 if daemon else 5000000)):
                raise RuntimeError("native service placement or lifetime mismatch")
            if daemon:
                cgroup_path(group)
                if (int(controls["RuntimeMaxUSec"]) != 180000000
                        or int(controls["RuntimeRandomizedExtraUSec"]) != 0):
                    raise RuntimeError("native daemon deadline mismatch")
            elif (not controls["RemainAfterExit"] or int(controls["MainPID"]) != 0
                  or controls["Result"] != "success" or int(controls["ExecMainStatus"]) != 0):
                raise RuntimeError("native client did not exit successfully")
        result = NativeIdentity(boot, name, invocation, group, job)
        if name == self.units[1]:
            result = dataclasses.replace(process_identity(int(controls["MainPID"]), result), argv=())
        return result

    def start(self, name):
        props = self.unit_properties(name)
        job = owned_job(user_bus(), name, lambda manager: manager.StartTransientUnit(
            name, "fail", props, dbus.Array([], signature="(sa(sv))"), timeout=5))
        return self.identity(name, job)

    def stop(self, owned):
        if owned.unit not in self.units or self.identity(owned.unit, owned.job) != owned:
            raise RuntimeError("native identity changed before stop")
        return owned_job(user_bus(), owned.unit,
                         lambda manager: manager.StopUnit(owned.unit, "fail", timeout=5), wait_seconds=20)

    def terminal(self, owned):
        bus = user_bus()
        try:
            manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                                   "/org/freedesktop/systemd1"), MANAGER)
            if any(str(row[1]) == owned.unit for row in manager.ListJobs(timeout=5)):
                raise RuntimeError("owned native job remains")
            try:
                unit = properties(bus, owned.unit, UNIT)
            except dbus.DBusException as error:
                if error.get_dbus_name() != "org.freedesktop.systemd1.NoSuchUnit":
                    raise
                return {"unit": owned.unit, "state": "absent"}
            invocation = bytes(unit["InvocationID"])
            if (unit["ActiveState"] != "inactive" or unit["SubState"] != "dead"
                    or int(unit["Job"][0]) != 0 or str(unit["Job"][1]) != "/"
                    or invocation not in (owned.invocation, b"", bytes(16))):
                raise RuntimeError("native unit lacks terminal state")
            if owned.unit != self.units[0] and int(properties(bus, owned.unit, SERVICE)["MainPID"]):
                raise RuntimeError("terminal native unit retains MainPID")
            return {"unit": owned.unit, "state": "inactive/dead", "invocation": invocation.hex()}
        finally:
            bus.close()

    def actors(self, parent, daemon):
        bus = user_bus()
        try:
            manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                                   "/org/freedesktop/systemd1"), MANAGER)
            rows = manager.GetUnitProcesses(parent.unit, timeout=5)
        finally:
            bus.close()
        result = []
        for group, pid, _name in rows:
            actor = process_identity(int(pid), daemon)
            if str(group) != actor.cgroup:
                raise RuntimeError("native process listing and cgroup disagree")
            result.append(actor)
        if not any(dataclasses.replace(actor, argv=()) == daemon for actor in result):
            raise RuntimeError("missing native main actor")
        return tuple(result)

    def rootlesskit(self, daemon, actors, info=None):
        parent = next((actor for actor in actors if actor.pid == daemon.pid), None)
        child_pid = int((self.r / "rootlesskit/child_pid").read_text())
        child = next((actor for actor in actors if actor.pid == child_pid), None)
        expected = ("rootlesskit", "--state-dir=" + str(self.r / "rootlesskit"), "--net=pasta",
                    "--mtu=65520", "--slirp4netns-sandbox=auto", "--slirp4netns-seccomp=auto",
                    "--disable-host-loopback", "--port-driver=implicit", "--copy-up=/etc",
                    "--copy-up=/run", "--propagation=rslave", "--detach-netns",
                    "/usr/bin/dockerd-rootless.sh", f"--config-file={self.p}/daemon.json", "--group=0")
        if (parent is None or dataclasses.replace(parent, argv=()) != daemon
                or parent.argv != expected
                or child is None or child.ppid != parent.pid):
            raise RuntimeError("RootlessKit native parent/child/configuration mismatch")
        for actor in (parent, child):
            if process_identity(actor.pid, actor) != actor:
                raise RuntimeError("RootlessKit PID/start changed")
        if info is not None:
            if (not isinstance(info, dict) or set(info) - {
                    "apiVersion", "version", "stateDir", "childPID", "networkDriver", "portDriver"}
                    or info.get("apiVersion") != "1.1.3" or info.get("version") != "3.2.0"
                    or info.get("stateDir") != str(self.r / "rootlesskit")
                    or type(info.get("childPID")) is not int or info["childPID"] != child.pid
                    or not isinstance(info.get("networkDriver"), dict)
                    or info["networkDriver"].get("driver") != "pasta"
                    or "portDriver" in info):
                raise RuntimeError("RootlessKit native API mismatch")
        return (parent, child)

    def managed_containerd(self, actors):
        config_bytes = (self.r / "exec/containerd/containerd.toml").read_bytes()
        config = tomllib.loads(config_bytes.decode("utf-8"))
        pid = int((self.r / "exec/containerd/containerd.pid").read_text())
        actor = next((item for item in actors if item.pid == pid), None)
        docker_pid = int((self.r / "docker.pid").read_text())
        docker = next((item for item in actors if item.pid == docker_pid), None)
        if (config.get("root") != str(self.p / "data/containerd/daemon")
                or config.get("state") != str(self.r / "exec/containerd/daemon")
                or config.get("grpc", {}).get("address") != str(self.sockets[2])
                or config.get("debug", {}).get("address") != str(self.sockets[3])
                or actor is None or docker is None or actor.ppid != docker.pid
                or docker.argv != ("dockerd", f"--config-file={self.p}/daemon.json", "--group=0")
                or process_identity(docker.pid, docker) != docker
                or actor.argv != ("/usr/bin/containerd", "--config",
                                                  str(self.r / "exec/containerd/containerd.toml"))
                or process_identity(pid, actor) != actor):
            raise RuntimeError("private managed-containerd metadata mismatch")
        if (config_bytes != (self.r / "exec/containerd/containerd.toml").read_bytes()
                or int((self.r / "exec/containerd/containerd.pid").read_text()) != actor.pid
                or int((self.r / "docker.pid").read_text()) != docker.pid):
            raise RuntimeError("managed-containerd private metadata changed")
        return {"identity": actor, "toml": config_bytes.decode("utf-8")}

    def docker_info(self, info):
        if (not isinstance(info, dict) or info.get("ServerVersion") != "29.9.0"
                or not isinstance(info.get("ID"), str) or not info["ID"]
                or info.get("DockerRootDir") != str(self.p / "data")
                or type(info.get("Containers")) is not int or info["Containers"] != 0
                or type(info.get("Images")) is not int or info["Images"] != 0
                or info.get("CgroupDriver") != "systemd" or info.get("CgroupVersion") != "2"
                or dict(info.get("DriverStatus", [])).get("driver-type") != "io.containerd.snapshotter.v1"
                or not {"name=rootless", "name=seccomp,profile=builtin", "name=cgroupns"}
                <= set(info.get("SecurityOptions", []))
                or info.get("Containerd", {}).get("Address") != str(self.sockets[2])):
            raise RuntimeError("private Docker zero-object/configured-default Info mismatch")
        return info["ID"]

    def socket_identity(self):
        result = []
        for path in self.sockets:
            metadata = path.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 1000:
                raise RuntimeError("private native socket mismatch")
            result.append((str(path), metadata.st_dev, metadata.st_ino, metadata.st_uid))
        return tuple(result)

    def closed_objects(self, parent, actors):
        group = cgroup_path(parent.cgroup)
        if present(group) and "populated 0" not in (group / "cgroup.events").read_text().splitlines():
            raise RuntimeError("native parent or descendant remains populated")
        bus = user_bus()
        try:
            manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                                   "/org/freedesktop/systemd1"), MANAGER)
            try:
                remaining = manager.GetUnitProcesses(parent.unit, timeout=5)
            except dbus.DBusException as error:
                if error.get_dbus_name() != "org.freedesktop.systemd1.NoSuchUnit":
                    raise
                remaining = []
            if remaining:
                raise RuntimeError("native parent process inventory is not empty")
        finally:
            bus.close()
        for actor in actors:
            try:
                start = int((PROC / str(actor.pid) / "stat").read_text().rsplit(")", 1)[1].split()[19])
            except FileNotFoundError:
                continue
            if start == actor.starttime:
                raise RuntimeError("recorded native PID/start remains alive")
        for group in {actor.pgrp for actor in actors}:
            if group <= 0:
                raise RuntimeError("missing recorded process group")
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                continue
            raise RuntimeError("recorded native process group still exists")
        for path in self.sockets:
            if present(path):
                raise RuntimeError("stale native socket requires root reconciliation")

    def invariants(self, owner, host, mounts, source):
        if process_identity(owner.pid, owner) != owner:
            raise RuntimeError("outside keeper identity changed")
        current = (PROC / "self/mountinfo").read_text()
        if current != mounts or str(self.p) in current or str(self.r) in current:
            raise RuntimeError("observer mount changed or exported a private path")
        if host_state() != host or digest_map(source) != source:
            raise RuntimeError("host or frozen input bytes changed")
        return {"contract": CONTRACT, "outside_holders": "unmeasured",
                "detached_namespace_identity": "unmeasured",
                "actor_security": "unmeasured", "observer_mounts_equal": True,
                "assumption": "no external actor of any UID acquires or receives direct or indirect namespace references"}

    def create_private_files(self):
        for path in (self.p, self.r):
            if any(parent.is_symlink() for parent in path.parents):
                raise RuntimeError("private ancestry contains a symlink")
            path.mkdir(mode=0o700)
        for name in ("home", "config", "xdgdata", "cache", "tmp", "docker-config"):
            (self.p / name).mkdir(mode=0o700)
        (self.r / "xdg").mkdir(mode=0o700)
        for path, value in ((self.p / "daemon.json", self.daemon_config()),
                            (self.p / "docker-config/config.json", {})):
            with path.open("x") as output:
                output.write(json.dumps(value, sort_keys=True) + "\n")
        return {str(path): (path.stat().st_dev, path.stat().st_ino) for path in (self.p, self.r)}

    def run(self, source):
        if source != frozen_inputs():
            raise RuntimeError("incomplete immutable source/native/oracle input map")
        os.umask(0o077)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(300)
        deadline = time.monotonic() + 300
        lock = os.open("/tmp/vespiary-heavy-validation.lock",
                       os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            boot = (PROC / "sys/kernel/random/boot_id").read_text().strip()
            placement = NativeIdentity(boot, "outside-keeper", b"", (PROC / "self/cgroup").read_text().strip()[3:], "")
            owner = process_identity(os.getpid(), placement)
            if os.getuid() != 1000 or os.getgid() != 1000 or digest_map(source) != source:
                raise RuntimeError("keeper user or frozen inputs mismatch")
            append_receipt(self.receipt, {"status": "pending", "contract": CONTRACT,
                           "nonce": self.nonce, "base": BASE, "source": source, "owner": owner,
                           "units": self.units, "persistent": str(self.p), "runtime": str(self.r),
                           "endpoint": self.uri, "keeper_seconds": 300, "outer_owner_seconds": 500})
            try:
                self.observe(owner, source, deadline)
            except BaseException as error:
                append_receipt(self.receipt.with_suffix(".failed.json"),
                               {"status": "failed-or-unknown", "error": repr(error), "source": source})
                raise
        finally:
            os.close(lock)
            signal.alarm(0)

    def observe(self, owner, source, deadline):
        host = host_state()
        mounts = (PROC / "self/mountinfo").read_text()
        self.invariants(owner, host, mounts, source)
        if any(present(path) for path in (self.p, self.r)):
            raise RuntimeError("private path already exists")
        if any(path.name.startswith(f"daemon-only-pending-{self.nonce}.")
               or path.name == f"daemon-only-root-closed-{self.nonce}.json" for path in REVIEWS.iterdir()
               if path != self.receipt):
            raise RuntimeError("native identity has historical companions")
        bus = user_bus()
        try:
            manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                                   "/org/freedesktop/systemd1"), MANAGER)
            names = {str(row[0]) for row in manager.ListUnits(timeout=5)}
            jobs = {str(row[1]) for row in manager.ListJobs(timeout=5)}
            if set(self.units) & (names | jobs):
                raise RuntimeError("native identity already exists")
        finally:
            bus.close()
        parent = self.start(self.units[0])
        limits = bounded_parent(parent.cgroup)
        paths = self.create_private_files()
        configuration = digest_map((self.p / "daemon.json", self.p / "docker-config/config.json"))
        source = {**source, **configuration}
        append_receipt(self.receipt.with_suffix(".parent.json"),
                       {"parent": parent, "limits": limits, "paths": paths, "host": host,
                        "observer_mounts": mounts, "configuration": configuration})
        if time.monotonic() > deadline - 210:
            raise RuntimeError("insufficient native lifetime remaining")
        self.invariants(owner, host, mounts, source)
        daemon = self.start(self.units[1])
        if not daemon.cgroup.startswith(parent.cgroup + "/"):
            raise RuntimeError("daemon outside bounded native parent")
        append_receipt(self.receipt.with_suffix(".daemon.json"), {"daemon": daemon})
        ready = min(deadline - 60, time.monotonic() + 30)
        while not all(present(path) for path in self.sockets):
            if time.monotonic() >= ready:
                raise RuntimeError("native private sockets readiness deadline")
            time.sleep(0.1)
        processes = self.actors(parent, daemon)
        required = {Path(actor.argv[0]).name for actor in processes if actor.argv}
        if not {"rootlesskit", "dockerd", "containerd", "pasta.avx2"} <= required:
            raise RuntimeError("required native actor missing")
        correlation = self.rootlesskit(daemon, processes)
        sockets = self.socket_identity()
        containerd = self.managed_containerd(processes)
        self.invariants(owner, host, mounts, source)
        info = self.start(self.units[2])
        daemon_id = self.docker_info(strict_json((self.p / "info.json").read_bytes()))
        if self.identity(daemon.unit, daemon.job) != daemon:
            raise RuntimeError("daemon invocation changed before native API")
        self.invariants(owner, host, mounts, source)
        api = self.start(self.units[3])
        if (self.p / "rootlesskit-status.json").read_bytes() != b"200":
            raise RuntimeError("RootlessKit API did not return exact HTTP 200")
        response = strict_json((self.p / "rootlesskit-info.json").read_bytes())
        if self.rootlesskit(daemon, processes, response) != correlation or self.socket_identity() != sockets:
            raise RuntimeError("RootlessKit socket or PID correlation changed")
        after = self.actors(parent, daemon)
        for actor in processes:
            if process_identity(actor.pid, actor) != actor:
                raise RuntimeError("native actor changed during API observation")
        processes = tuple(set(processes) | set(after))
        if self.managed_containerd(processes) != containerd or self.identity(daemon.unit, daemon.job) != daemon:
            raise RuntimeError("managed runtime or invocation changed during API observation")
        self.invariants(owner, host, mounts, source)
        append_receipt(self.receipt.with_suffix(".observation.json"),
                       {"actors": processes, "containerd": containerd, "rootlesskit": response,
                        "rootlesskit_identity": correlation, "daemon_id": daemon_id, "sockets": sockets,
                        "clients": (info, api), "limits": bounded_parent(parent.cgroup)})
        if time.monotonic() > deadline - 65:
            raise RuntimeError("insufficient positive teardown time")
        stops = [(unit.unit, self.stop(unit)) for unit in (api, info, daemon)]
        terminals = [self.terminal(unit) for unit in (api, info, daemon)]
        self.closed_objects(parent, processes)
        closure = self.invariants(owner, host, mounts, source)
        append_receipt(self.receipt.with_suffix(".stopped.json"),
                       {"jobs": stops, "terminals": terminals, "native_service_closure": closure})
        parent_stop = self.stop(parent)
        parent_terminal = self.terminal(parent)
        self.closed_objects(parent, processes)
        final_terminals = [self.terminal(unit) for unit in (api, info, daemon)]
        if time.monotonic() > deadline:
            raise RuntimeError("keeper exceeded 300 seconds")
        self.invariants(owner, host, mounts, source)
        append_receipt(self.receipt.with_suffix(".closed.json"),
                       {"status": "native-service-closed-awaiting-root", "source": source,
                        "parent_stop_job": parent_stop, "parent_terminal": parent_terminal,
                        "final_service_terminals": final_terminals,
                        "native_service_closure": closure, "retained_paths": paths,
                        "root_acceptance": "pending distinct companion and actual canonical lock release"})


if __name__ == "__main__":
    raise SystemExit("source preparation only; root must freeze inputs and separately authorize an assigned Attempt")
