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
import subprocess
import time
import tomllib

from native_client_entry import client_argv, read_witness


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
MAX_RESULT = 2097152
MAX_FILE = 1048576
MAX_INPUT = 134217728
MAX_INPUT_TOTAL = 536870912
LOCK = Path("/tmp/vespiary-heavy-validation.lock")
dbus = None
owned_job = None
user_bus = None


def setup_native():
    global dbus, owned_job, user_bus
    import dbus as binding
    from systemd_job import owned_job as job, user_bus as bus
    dbus, owned_job, user_bus = binding, job, bus


def present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def strict_json(body, limit=MAX_RESPONSE):
    if len(body) > limit:
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
    result = {}
    remaining = MAX_INPUT_TOTAL
    for path in paths:
        body = read_bounded(Path(path).resolve(), min(MAX_INPUT, remaining))
        remaining -= len(body)
        result[str(path)] = hashlib.sha256(body).hexdigest()
    return result


def frozen_inputs():
    manifest = Path(__file__).resolve().parents[2] / "docs/dev/verify-runtime-20261020/native-api-inputs.sha256"
    expected = {}
    for line in read_bounded(manifest, MAX_FILE).decode().splitlines():
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
    encoder = json.JSONEncoder(sort_keys=True, default=lambda obj: obj.hex()
                               if isinstance(obj, bytes) else dataclasses.asdict(obj))
    body = bytearray()
    for piece in encoder.iterencode(value):
        raw = piece.encode()
        if len(body) + len(raw) + 1 > MAX_RESULT:
            raise RuntimeError("receipt exceeds matching writer/reader bound")
        body.extend(raw)
    body.extend(b"\n")
    write_evidence(path, body)


def write_evidence(path, body):
    if len(body) > MAX_RESULT:
        raise RuntimeError("receipt exceeds matching writer/reader bound")
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
            key: read_bounded(path / key, MAX_FILE).decode().strip() if present(path / key) else None
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
    enforce = read_bounded(Path("/sys/fs/selinux/enforce"), MAX_FILE).decode().strip()
    if enforce != "1":
        raise RuntimeError("host SELinux is not Enforcing")
    files = [Path("/proc/sys/net/ipv4/ip_forward"),
             Path("/proc/sys/net/ipv6/conf/all/forwarding"), Path("/etc/subuid"),
             Path("/etc/subgid"), Path("/etc/docker/daemon.json"),
             Path("/usr/lib/systemd/system/docker.service"),
             Path("/usr/lib/systemd/user/docker.service")]
    listeners = {}
    for name in ("tcp", "tcp6"):
        rows = read_bounded(Path(f"/proc/self/net/{name}"), MAX_FILE).decode().splitlines()[1:]
        listeners[name] = sorted(row.split()[1] for row in rows if row.split()[3] == "0A")
    return {"enforce": enforce, "run_label": os.getxattr("/run", "security.selinux").hex(),
            "listeners": listeners,
            "files": {str(path): hashlib.sha256(read_bounded(path, MAX_FILE)).hexdigest()
                      if present(path) else None for path in files}}


@dataclasses.dataclass(frozen=True)
class UnitIdentity:
    boot: str
    unit: str
    invocation: bytes
    cgroup: str
    job: str


@dataclasses.dataclass(frozen=True)
class ProcessIdentity(UnitIdentity):
    pid: int
    starttime: int
    ppid: int
    pgrp: int
    argv: tuple[str, ...]

    def __post_init__(self):
        if min(self.pid, self.starttime, self.ppid, self.pgrp) <= 0 or not self.boot or not self.argv:
            raise RuntimeError("process identity requires actual positive metadata")


@dataclasses.dataclass
class Observation:
    owner: ProcessIdentity
    source: dict[str, str]
    host: dict
    mounts: str
    intents: list[str] = dataclasses.field(default_factory=list)
    units: list[UnitIdentity] = dataclasses.field(default_factory=list)
    processes: list[ProcessIdentity] = dataclasses.field(default_factory=list)
    clients: list[dict] = dataclasses.field(default_factory=list)

def process_identity(pid, placement):
    root = PROC / str(pid)
    boot = read_bounded(PROC / "sys/kernel/random/boot_id", MAX_FILE).decode().strip()
    before = read_bounded(root / "stat", MAX_FILE).decode().rsplit(")", 1)[1].split()
    group = read_bounded(root / "cgroup", MAX_FILE).decode().strip()
    if not group.startswith("0::"):
        raise RuntimeError("not unified cgroup v2")
    group = group[3:]
    if group != placement.cgroup and not group.startswith(placement.cgroup + "/"):
        raise RuntimeError("observed process escaped native placement")
    result = ProcessIdentity(
        boot, placement.unit, placement.invocation, group, placement.job,
        pid, int(before[19]), int(before[1]), int(before[2]),
        tuple(x.decode("utf-8") for x in read_bounded(root / "cmdline", MAX_FILE).split(b"\0") if x),
    )
    after = read_bounded(root / "stat", MAX_FILE).decode().rsplit(")", 1)[1].split()
    if (before[19] != after[19] or boot != placement.boot
            or boot != read_bounded(PROC / "sys/kernel/random/boot_id", MAX_FILE).decode().strip()
            or read_bounded(root / "cgroup", MAX_FILE).decode().strip() != "0::" + group):
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
        return client_argv("rootlesskit", self.p, self.r)

    def child_argv(self, mode):
        if mode not in ("finite", "recheck"):
            raise RuntimeError("child outside fixed native work")
        entry = Path(__file__).resolve().with_name("native_python_entry.py")
        return ["/usr/bin/python3", "-I", "-S", "-B", str(entry), mode, self.nonce]


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
            else:
                kind = "docker" if name == self.units[2] else "rootlesskit"
                argv = ["/usr/bin/python3", "-I", "-S", "-B",
                        str(Path(__file__).resolve().with_name("native_client_entry.py")), kind, self.nonce]
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
                           ("LimitFSIZE", dbus.UInt64(MAX_RESPONSE)),
                           ("LimitFSIZESoft", dbus.UInt64(MAX_RESPONSE)),
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
        boot = read_bounded(PROC / "sys/kernel/random/boot_id", MAX_FILE).decode().strip()
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
        return UnitIdentity(boot, name, invocation, group, job)

    def start(self, name, observation):
        self.invariants(observation.owner, observation.host, observation.mounts, observation.source)
        props = self.unit_properties(name)
        intent = self.receipt.with_suffix(f".{name}.start.json")
        append_receipt(intent, {"boot": observation.owner.boot, "unit": name,
                       "description": f"goal330-native-api {self.nonce}", "properties": list(props)})
        observation.intents.append(name)
        if name in self.units[2:]:
            parent = observation.units[0]
            kind = "docker" if name == self.units[2] else "rootlesskit"
            entry = Path(__file__).resolve().with_name("native_client_entry.py")
            append_receipt(self.p / f"{kind}-plan.json", {
                "boot": observation.owner.boot, "unit": name,
                "cgroup": parent.cgroup + "/" + name, "entry": digest_map((entry,))})
        job = ""
        try:
            job = owned_job(user_bus(), name, lambda manager: manager.StartTransientUnit(
                name, "fail", props, dbus.Array([], signature="(sa(sv))"), timeout=5))
            bound = self.identity(name, job)
        except BaseException:
            if name in self.units[2:]:
                evidence = self.client_output(UnitIdentity(observation.owner.boot, name, b"", "", job))
                observation.clients.append(evidence)
                append_receipt(self.receipt.with_suffix(f".{name}.output.json"), evidence)
            raise
        observation.units.append(bound)
        append_receipt(self.receipt.with_suffix(f".{name}.bound.json"), {"unit": bound})
        if name in self.units[2:]:
            try:
                actor = self.completed_client(bound)
            finally:
                evidence = self.client_output(bound)
                observation.clients.append(evidence)
                append_receipt(self.receipt.with_suffix(f".{name}.output.json"), evidence)
            observation.processes.append(actor)
        return bound

    def client_output(self, unit):
        kind = "docker" if unit.unit == self.units[2] else "rootlesskit"
        stem = "info" if kind == "docker" else "rootlesskit-status"
        names = [f"{stem}.json", f"{stem}.stderr"]
        if kind == "rootlesskit":
            names.append("rootlesskit-info.json")
        buffers = {}
        for name in names:
            path = self.p / name
            try:
                raw = read_bounded(path, MAX_RESPONSE)
                buffers[name] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "raw": raw.hex()}
            except BaseException as error:
                buffers[name] = {"error": repr(error)}
        witness = None
        completion = None
        error = None
        try:
            witness = read_witness(self.p / f"{kind}-entry.json")
            bus = user_bus()
            try:
                service = properties(bus, unit.unit, SERVICE)
                completion = {key: int(service[key]) for key in ("ExecMainPID", "ExecMainCode", "ExecMainStatus")}
                completion["Result"] = str(service["Result"])
                if (witness["boot"] != unit.boot or witness["unit"] != unit.unit
                        or bytes.fromhex(witness["invocation"]) != unit.invocation
                        or completion != {"ExecMainPID": witness["pid"], "ExecMainCode": 1,
                                          "ExecMainStatus": 0, "Result": "success"}
                        or witness["argv"] != client_argv(kind, self.p, self.r)
                        or self.identity(unit.unit, unit.job) != unit):
                    raise RuntimeError("raw output pre-exec/job/invocation/ExecMain join failed")
            finally:
                bus.close()
        except BaseException as failure:
            error = repr(failure)
        return {"unit": dataclasses.asdict(unit), "witness": witness, "completion": completion,
                "join_error": error, "buffers": buffers}

    def completed_client(self, unit):
        kind = "docker" if unit.unit == self.units[2] else "rootlesskit"
        witness = read_witness(self.p / f"{kind}-entry.json")
        plan = strict_json(read_bounded(self.p / f"{kind}-plan.json", 16384))
        bus = user_bus()
        try:
            service = properties(bus, unit.unit, SERVICE)
        finally:
            bus.close()
        if (witness["boot"] != unit.boot or witness["unit"] != unit.unit
                or bytes.fromhex(witness["invocation"]) != unit.invocation
                or int(service["ExecMainPID"]) != witness["pid"]
                or int(service["ExecMainCode"]) != 1 or int(service["ExecMainStatus"]) != 0
                or service["Result"] != "success"
                or witness["argv"] != client_argv(kind, self.p, self.r)
                or witness["cgroup"] != plan["cgroup"]
                or (unit.cgroup and witness["cgroup"] != unit.cgroup)
                or self.identity(unit.unit, unit.job) != unit):
            raise RuntimeError("native short-client pre-exec/completion mismatch")
        return ProcessIdentity(unit.boot, unit.unit, unit.invocation, witness["cgroup"], unit.job,
                               witness["pid"], witness["starttime"], witness["ppid"],
                               witness["pgrp"], tuple(witness["argv"]))


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
        bus = user_bus()
        try:
            main = int(properties(bus, daemon.unit, SERVICE)["MainPID"])
        finally:
            bus.close()
        if not any(actor.pid == main for actor in result):
            raise RuntimeError("missing native main actor")
        return tuple(result)

    def rootlesskit(self, daemon, actors, info=None):
        bus = user_bus()
        try:
            main = int(properties(bus, daemon.unit, SERVICE)["MainPID"])
        finally:
            bus.close()
        parent = next((actor for actor in actors if actor.pid == main), None)
        child_pid = int(read_bounded(self.r / "rootlesskit/child_pid", 128))
        child = next((actor for actor in actors if actor.pid == child_pid), None)
        expected = ("rootlesskit", "--state-dir=" + str(self.r / "rootlesskit"), "--net=pasta",
                    "--mtu=65520", "--slirp4netns-sandbox=auto", "--slirp4netns-seccomp=auto",
                    "--disable-host-loopback", "--port-driver=implicit", "--copy-up=/etc",
                    "--copy-up=/run", "--propagation=rslave", "--detach-netns",
                    "/usr/bin/dockerd-rootless.sh", f"--config-file={self.p}/daemon.json", "--group=0")
        if (parent is None or parent.invocation != daemon.invocation
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
        config_bytes = read_bounded(self.r / "exec/containerd/containerd.toml", MAX_RESPONSE)
        config = tomllib.loads(config_bytes.decode("utf-8"))
        pid = int(read_bounded(self.r / "exec/containerd/containerd.pid", 128))
        actor = next((item for item in actors if item.pid == pid), None)
        docker_pid = int(read_bounded(self.r / "docker.pid", 128))
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
        if (config_bytes != read_bounded(self.r / "exec/containerd/containerd.toml", MAX_RESPONSE)
                or int(read_bounded(self.r / "exec/containerd/containerd.pid", 128)) != actor.pid
                or int(read_bounded(self.r / "docker.pid", 128)) != docker.pid):
            raise RuntimeError("managed-containerd private metadata changed")
        return {"identity": actor, "toml": config_bytes.decode("utf-8"),
                "size": len(config_bytes), "sha256": hashlib.sha256(config_bytes).hexdigest()}

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
        if present(group) and "populated 0" not in read_bounded(group / "cgroup.events", MAX_FILE).decode().splitlines():
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
                start = int(read_bounded(PROC / str(actor.pid) / "stat", MAX_FILE).decode().rsplit(")", 1)[1].split()[19])
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
        current = read_bounded(PROC / "self/mountinfo", MAX_FILE).decode()
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

    def finite(self, owner, source):
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(300)
        deadline = time.monotonic() + 300
        observation = Observation(owner, source, host_state(), read_bounded(PROC / "self/mountinfo", MAX_FILE).decode())
        failure = None
        closure = None
        try:
            self.observe(observation, deadline)
        except BaseException as error:
            failure = repr(error)
        try:
            closure = self.teardown(observation)
        except BaseException as error:
            failure = failure or repr(error)
        try:
            self.invariants(owner, observation.host, observation.mounts, observation.source)
        except BaseException as error:
            failure = failure or repr(error)
        status = "retained-unknown" if closure is None else "failed-but-closed" if failure else "qualified-and-closed"
        append_receipt(self.receipt.with_suffix(".finite-result.json"), {
            "status": status, "failure": failure, "closure": closure,
            "observation": dataclasses.asdict(observation)})
        return status

    def recheck(self):
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(90)
        result = strict_json(read_bounded(self.receipt.with_suffix(".finite-result.json"), MAX_RESULT), MAX_RESULT)
        if result["status"] not in ("qualified-and-closed", "failed-but-closed") or result["closure"] is None:
            raise RuntimeError("finite native closure remains unknown")
        observation = restore_observation(result["observation"])
        resource_invariants(self, observation.owner, observation.mounts)
        for unit in observation.units:
            self.terminal(unit)
        if observation.units:
            self.closed_objects(observation.units[0], observation.processes)
        elif observation.intents:
            raise RuntimeError("unbound native intent remains")
        resource_invariants(self, observation.owner, observation.mounts)
        try:
            self.invariants(observation.owner, observation.host, observation.mounts, observation.source)
        except BaseException as error:
            result["status"] = "failed-but-closed"
            result["failure"] = repr(error)
        append_receipt(self.receipt.with_suffix(".recheck-result.json"), result)
        return result["status"]

    def observe(self, observation, deadline):
        owner, source, host, mounts = observation.owner, observation.source, observation.host, observation.mounts
        self.invariants(owner, host, mounts, source)
        if any(present(path) for path in (self.p, self.r)):
            raise RuntimeError("private path already exists")
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
        parent = self.start(self.units[0], observation)
        limits = bounded_parent(parent.cgroup)
        paths = self.create_private_files()
        observation.source = {**source, **digest_map((self.p / "daemon.json", self.p / "docker-config/config.json"))}
        append_receipt(self.receipt.with_suffix(".parent.json"),
                       {"parent": parent, "limits": limits, "paths": paths, "host": host,
                        "observer_mounts": mounts, "configuration": observation.source})
        if time.monotonic() > deadline - 210:
            raise RuntimeError("insufficient native lifetime remaining")
        daemon = self.start(self.units[1], observation)
        if not daemon.cgroup.startswith(parent.cgroup + "/"):
            raise RuntimeError("daemon outside bounded native parent")
        ready = min(deadline - 70, time.monotonic() + 30)
        while not all(present(path) for path in self.sockets):
            if time.monotonic() >= ready:
                raise RuntimeError("native private sockets readiness deadline")
            time.sleep(0.1)
        processes = self.actors(parent, daemon)
        observation.processes.extend(processes)
        required = {Path(actor.argv[0]).name for actor in processes if actor.argv}
        if not {"rootlesskit", "dockerd", "containerd"} <= required or not {"pasta", "pasta.avx2"} & required:
            raise RuntimeError("required native actor missing")
        correlation = self.rootlesskit(daemon, processes)
        sockets = self.socket_identity()
        containerd = self.managed_containerd(processes)
        info = self.start(self.units[2], observation)
        daemon_id = self.docker_info(strict_json(client_buffer(observation, "info.json")))
        if self.identity(daemon.unit, daemon.job) != daemon:
            raise RuntimeError("daemon invocation changed before native API")
        api = self.start(self.units[3], observation)
        if client_buffer(observation, "rootlesskit-status.json") != b"200":
            raise RuntimeError("RootlessKit API did not return exact HTTP 200")
        response = strict_json(client_buffer(observation, "rootlesskit-info.json"))
        if self.rootlesskit(daemon, processes, response) != correlation or self.socket_identity() != sockets:
            raise RuntimeError("RootlessKit socket or PID correlation changed")
        after = self.actors(parent, daemon)
        observation.processes.extend(actor for actor in after if actor not in observation.processes)
        for actor in processes:
            if process_identity(actor.pid, actor) != actor:
                raise RuntimeError("native actor changed during API observation")
        if self.managed_containerd(after) != containerd or self.identity(daemon.unit, daemon.job) != daemon:
            raise RuntimeError("managed runtime or invocation changed during API observation")
        self.invariants(owner, host, mounts, observation.source)
        append_receipt(self.receipt.with_suffix(".observation.json"),
                       {"actors": observation.processes, "containerd": containerd, "rootlesskit": response,
                        "rootlesskit_identity": correlation, "daemon_id": daemon_id, "sockets": sockets,
                        "clients": observation.clients, "limits": bounded_parent(parent.cgroup)})
        if time.monotonic() > deadline - 65:
            raise RuntimeError("insufficient positive teardown time")

    def teardown(self, observation):
        failures = []
        stop_jobs = []
        bound = {unit.unit: unit for unit in observation.units}
        if set(observation.intents) - set(bound):
            failures.append("start reply/binding is unknown; root must reconcile exact durable intent")
        for name in reversed(observation.intents):
            if name == self.units[0] or name not in bound:
                continue
            try:
                unit = bound[name]
                stop_jobs.append((unit.unit, self.stop(unit)))
                self.terminal(unit)
            except BaseException as error:
                failures.append(repr(error))
        if failures:
            raise RuntimeError("; ".join(failures))
        if not observation.units:
            return {"no_native_mutation": not observation.intents}
        parent = bound[self.units[0]]
        self.closed_objects(parent, observation.processes)
        resource_invariants(self, observation.owner, observation.mounts)
        for unit in observation.units[1:]:
            self.terminal(unit)
        parent_job = self.stop(parent)
        self.terminal(parent)
        self.closed_objects(parent, observation.processes)
        resource_invariants(self, observation.owner, observation.mounts)
        return {"contract": CONTRACT, "parent_stop_job": parent_job,
                "service_stop_jobs": stop_jobs,
                "outside_holders": "unmeasured", "detached_namespace_identity": "unmeasured",
                "actor_security": "unmeasured", "observer_mounts_equal": True,
                "assumption": "no external actor of any UID acquires or receives direct or indirect namespace references"}


def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise RuntimeError("bounded native evidence input exceeded or is not regular")
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise RuntimeError("bounded native evidence input exceeded")
    return body


def client_buffer(observation, name):
    evidence = next(row for row in observation.clients if name in row["buffers"])
    if evidence["join_error"] is not None:
        raise RuntimeError("client output lacks positive completion join")
    return bytes.fromhex(evidence["buffers"][name]["raw"])


def resource_invariants(attempt, owner, mounts):
    if process_identity(owner.pid, owner) != owner:
        raise RuntimeError("outside holder boot/PID/start changed")
    current = read_bounded(PROC / "self/mountinfo", MAX_FILE).decode()
    if current != mounts or str(attempt.p) in current or str(attempt.r) in current:
        raise RuntimeError("observer mount changed or exported a private path")


def park_unknown(attempt, error):
    try:
        append_receipt(attempt.receipt.with_suffix(".holder-unknown.json"),
                       {"status": "retained-unknown", "error": repr(error)})
    except BaseException:
        pass
    while True:
        try:
            signal.pause()
        except BaseException:
            pass


def acquire_lock():
    path = LOCK
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        metadata = os.fstat(descriptor)
        current = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 1000
                or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
                or os.get_inheritable(descriptor)):
            raise RuntimeError("canonical descriptor identity/noninheritance mismatch")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor, (metadata.st_dev, metadata.st_ino)
    except BaseException:
        os.close(descriptor)
        raise


def holder_budget(owner):
    rows = []
    leaf = cgroup_path(owner.cgroup)
    for path in (leaf, *leaf.parents):
        if path == CGROUP.parent:
            break
        rows.append({"path": str(path), **{name: read_bounded(path / name, MAX_FILE).decode().strip()
                    if present(path / name) else None for name in
                    ("cpu.max", "memory.max", "memory.swap.max", "pids.max")}})
    usable = [row for row in rows if row["cpu.max"] and row["memory.max"] and row["memory.swap.max"] == "0"]
    if not any(row["cpu.max"].split()[0] != "max"
               and int(row["cpu.max"].split()[0]) <= 4 * int(row["cpu.max"].split()[1])
               and row["memory.max"] != "max" and int(row["memory.max"]) <= 4294967296 for row in usable):
        raise RuntimeError("outside holder/finite child budget needs reviewed four-CPU/four-GiB zero-swap ancestor")
    return rows


def request_recovery(_signal, _frame):
    raise InterruptedError("outside holder interruption requests retained recovery")


def wait_finite(attempt, child, identity, mode, seconds):
    timed_out = False
    try:
        code = child.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        if process_identity(child.pid, identity) != identity:
            raise RuntimeError("finite child identity changed before cancellation")
        child.terminate()
        try:
            code = child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            code = child.wait(timeout=5)
    record = {"child": identity, "operation": mode, "returncode": code, "timed_out": timed_out}
    append_receipt(attempt.receipt.with_suffix(f".{mode}-exit.json"), record)
    if timed_out:
        raise RuntimeError("finite work exceeded deadline; retain physical custody")
    return record


def hold_attempt(attempt):
    source = frozen_inputs()
    boot = read_bounded(PROC / "sys/kernel/random/boot_id", MAX_FILE).decode().strip()
    group = read_bounded(PROC / "self/cgroup", MAX_FILE).decode().strip()
    if not group.startswith("0::") or os.getuid() != 1000 or os.getgid() != 1000:
        raise RuntimeError("outside holder user/cgroup mismatch")
    owner = process_identity(os.getpid(), UnitIdentity(boot, "outside-holder", b"", group[3:], ""))
    budget = holder_budget(owner)
    descriptor, lock_identity = acquire_lock()
    child = None
    ceiling = time.monotonic() + 500
    try:
        signal.signal(signal.SIGTERM, request_recovery)
        if any(present(path) for path in (attempt.p, attempt.r)) or any(
            path.name.startswith(f"daemon-only-pending-{attempt.nonce}.")
            or path.name == f"daemon-only-root-closed-{attempt.nonce}.json" for path in REVIEWS.iterdir()
        ):
            raise RuntimeError("assigned identity has retained paths or primary/companion history")
        append_receipt(attempt.receipt, {"status": "pending", "nonce": attempt.nonce, "base": BASE,
                       "source": source, "owner": owner, "budget": budget, "lock": lock_identity,
                       "descriptor": descriptor, "inheritable": False, "units": attempt.units,
                       "executable": os.readlink(PROC / "self/exe"),
                       "endpoint": attempt.uri, "persistent": str(attempt.p), "runtime": str(attempt.r),
                       "finite_seconds": 300, "owner_recovery_ceiling": 500,
                       "mounts": read_bounded(PROC / "self/mountinfo", MAX_FILE).decode()})
        child = subprocess.Popen(attempt.child_argv("finite"),
                                 env=trusted_environment(), close_fds=True, start_new_session=True)
        finite = process_identity(child.pid, UnitIdentity(boot, "finite-observer", b"", owner.cgroup, ""))
        append_receipt(attempt.receipt.with_suffix(".finite-child.json"), {"child": finite})
        exit_record = wait_finite(attempt, child, finite, "finite", 330)
        raw = read_bounded(attempt.receipt.with_suffix(".finite-result.json"), MAX_RESULT)
        result = strict_json(raw, MAX_RESULT)
        write_evidence(attempt.receipt.with_suffix(".finite-buffer.json"), raw)
        if time.monotonic() >= ceiling:
            raise RuntimeError("outer recovery ceiling reached; retain physical custody")
        if result["status"] not in ("qualified-and-closed", "failed-but-closed"):
            raise RuntimeError("finite native closure remains unknown")
        observation = restore_observation(result["observation"])
        if observation.owner != owner or any(observation.source.get(path) != digest for path, digest in source.items()):
            raise RuntimeError("finite result differs from original holder/source binding")
        failed = result["status"] == "failed-but-closed"
        child = subprocess.Popen(attempt.child_argv("recheck"),
                                 env=trusted_environment(), close_fds=True, start_new_session=True)
        recheck = process_identity(child.pid, UnitIdentity(boot, "closure-recheck", b"", owner.cgroup, ""))
        append_receipt(attempt.receipt.with_suffix(".recheck-child.json"), {"child": recheck})
        recheck_exit = wait_finite(attempt, child, recheck, "recheck", 100)
        checked_raw = read_bounded(attempt.receipt.with_suffix(".recheck-result.json"), MAX_RESULT)
        checked = strict_json(checked_raw, MAX_RESULT)
        write_evidence(attempt.receipt.with_suffix(".recheck-buffer.json"), checked_raw)
        if (recheck_exit["returncode"] != 0 or checked["status"] not in ("qualified-and-closed", "failed-but-closed")
                or checked["closure"] != result["closure"] or checked["observation"] != result["observation"]):
            raise RuntimeError("finite positive recheck failed or changed the bound observation")
        if time.monotonic() >= ceiling:
            raise RuntimeError("outer recovery ceiling reached after positive closure")
        result = checked
        if failed or exit_record["returncode"] != 0:
            result["status"] = "failed-but-closed"
            if exit_record["returncode"] != 0:
                result["failure"] = "finite observer exited abnormally"
        append_receipt(attempt.receipt.with_suffix(".holder-closed.json"),
                       {"status": result["status"], "lock": lock_identity, "owner": owner,
                        "failure": result["failure"],
                        "finite_exit": exit_record, "recheck_exit": recheck_exit,
                        "finite_result": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                        "recheck_result": {"size": len(checked_raw), "sha256": hashlib.sha256(checked_raw).hexdigest()},
                        "root_acceptance": "pending distinct companion and actual same-inode lock release"})
        current = os.fstat(descriptor)
        path = LOCK.lstat()
        if (current.st_dev, current.st_ino) != lock_identity or (path.st_dev, path.st_ino) != lock_identity:
            raise RuntimeError("canonical lock identity changed before positive release")
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        return result["status"]
    except BaseException as error:
        if child is not None and child.poll() is None:
            try:
                child.terminate()
                child.wait(timeout=5)
            except BaseException:
                pass
        park_unknown(attempt, error)


def restore_observation(value):
    def unit(row):
        return UnitIdentity(row["boot"], row["unit"], bytes.fromhex(row["invocation"]), row["cgroup"], row["job"])
    def process(row):
        return ProcessIdentity(**dataclasses.asdict(unit(row)), pid=row["pid"], starttime=row["starttime"],
                               ppid=row["ppid"], pgrp=row["pgrp"], argv=tuple(row["argv"]))
    return Observation(process(value["owner"]), value["source"], value["host"], value["mounts"],
                       list(value["intents"]), [unit(row) for row in value["units"]],
                       [process(row) for row in value["processes"]], list(value.get("clients", [])))


def trusted_environment():
    return {"PATH": "/usr/bin:/bin", "HOME": "/home/zack", "LC_ALL": "C", "LANG": "C",
            "DBUS_SESSION_BUS_ADDRESS": BUS, "GI_TYPELIB_PATH": "/usr/lib64/girepository-1.0"}


if __name__ == "__main__":
    raise SystemExit("source preparation only; use the separately reviewed native Python entry/profile")
