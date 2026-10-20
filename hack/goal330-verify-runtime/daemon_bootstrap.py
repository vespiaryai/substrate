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
import signal
import stat
import time
import tomllib

import dbus

from systemd_job import owned_job, user_bus


NONCE = "18ec13b3d43234b8ab4f79fbc49e0c1d"
BASE = "de861e9585cc3bc92fb0d87c0da37dee4ca765a2"
P = Path(f"/home/zack/.local/share/vesverify{NONCE}")
R = Path(f"/run/user/1000/vesverify{NONCE}")
SLICE = f"vesverify{NONCE}.slice"
DAEMON = f"vesverify{NONCE}-daemon.service"
INFO = f"vesverify{NONCE}-info.service"
RECEIPT = Path(f"/home/zack/.codex/orchestrate/vespiary-goal330/reviews/daemon-only-pending-{NONCE}.json")
URI = f"unix://{R}/docker.sock"
BUS = "unix:path=/run/user/1000/bus"
MANAGER = "org.freedesktop.systemd1.Manager"
UNIT = "org.freedesktop.systemd1.Unit"
SERVICE = "org.freedesktop.systemd1.Service"
CGROUP = Path("/sys/fs/cgroup")
PROC = Path("/proc")


def present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


@dataclasses.dataclass(frozen=True)
class UnitIdentity:
    name: str
    invocation: bytes
    cgroup: str
    job: str


@dataclasses.dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    starttime: int
    ppid: int
    cgroup: str
    argv: tuple[str, ...]
    namespaces: tuple[tuple[str, str], ...]


@dataclasses.dataclass(frozen=True)
class DetachedNetns:
    child: ProcessIdentity
    path: str
    device: int
    inode: int
    mount: str


def daemon_config():
    return {
        "data-root": str(P / "data"),
        "exec-root": str(R / "exec"),
        "pidfile": str(R / "docker.pid"),
        "hosts": [URI],
        "exec-opts": ["native.cgroupdriver=systemd"],
        "cgroup-parent": SLICE,
        "default-cgroupns-mode": "private",
        "ip": "127.0.0.1",
        "default-network-opts": {
            "bridge": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"}
        },
        "features": {"containerd-snapshotter": True, "embedded-containerd": False},
        "max-concurrent-downloads": 1,
        "max-download-attempts": 1,
        "shutdown-timeout": 10,
    }


def daemon_argv():
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(P / "home"),
        "XDG_CONFIG_HOME": str(P / "config"),
        "XDG_DATA_HOME": str(P / "xdgdata"),
        "XDG_CACHE_HOME": str(P / "cache"),
        "XDG_RUNTIME_DIR": str(R / "xdg"),
        "TMPDIR": str(P / "tmp"),
        "DBUS_SESSION_BUS_ADDRESS": BUS,
        "DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": str(R / "rootlesskit"),
        "CONTAINERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": str(R / "no-standalone-containerd"),
        "DOCKERD_ROOTLESS_ROOTLESSKIT_NET": "pasta",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER": "implicit",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS": "true",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK": "true",
    }
    return ["/usr/bin/env", "-i", *[f"{key}={value}" for key, value in env.items()],
            "/usr/bin/dockerd-rootless.sh", f"--config-file={P}/daemon.json", "--group=0"]


def slice_properties():
    return dbus.Array([
        ("Description", dbus.String(f"goal330 {NONCE}")),
        ("StopWhenUnneeded", dbus.Boolean(False)),
        ("CPUQuotaPerSecUSec", dbus.UInt64(2000000)),
        ("MemoryMax", dbus.UInt64(4294967296)),
        ("MemorySwapMax", dbus.UInt64(0)),
        ("TasksMax", dbus.UInt64(512)),
    ], signature="(sv)")


def daemon_properties():
    argv = daemon_argv()
    return dbus.Array([
        ("Description", dbus.String(f"goal330 {NONCE}")),
        ("Type", dbus.String("exec")),
        ("Slice", dbus.String(SLICE)),
        ("Delegate", dbus.Boolean(True)),
        ("Restart", dbus.String("no")),
        ("KillMode", dbus.String("control-group")),
        ("SendSIGKILL", dbus.Boolean(True)),
        ("TimeoutStartUSec", dbus.UInt64(15000000)),
        ("RuntimeMaxUSec", dbus.UInt64(180000000)),
        ("RuntimeRandomizedExtraUSec", dbus.UInt64(0)),
        ("TimeoutStopUSec", dbus.UInt64(15000000)),
        ("ExecStart", dbus.Array([(argv[0], argv, False)], signature="(sasb)")),
    ], signature="(sv)")


def properties(bus, name, interface):
    manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1"), MANAGER)
    path = manager.GetUnit(name, timeout=5)
    obj = bus.get_object("org.freedesktop.systemd1", path)
    return dbus.Interface(obj, "org.freedesktop.DBus.Properties").GetAll(interface, timeout=5)


def identity(bus, name, job):
    unit = properties(bus, name, UNIT)
    kind = "org.freedesktop.systemd1.Slice" if name == SLICE else SERVICE
    controls = properties(bus, name, kind)
    if (not unit["Transient"] or unit["ActiveState"] != "active"
            or unit["Description"] != f"goal330 {NONCE}"):
        raise RuntimeError("owned unit identity mismatch")
    invocation = bytes(unit["InvocationID"])
    cgroup = str(controls["ControlGroup"])
    if (len(invocation) != 16 or not any(invocation)
            or (name != INFO and not cgroup.startswith("/"))):
        raise RuntimeError("missing invocation or cgroup identity")
    if name == SLICE and unit["StopWhenUnneeded"]:
        raise RuntimeError("slice can disappear before postflight")
    if name == DAEMON and (controls["Slice"] != SLICE
                           or controls["KillMode"] != "control-group"
                           or controls["Restart"] != "no"
                           or int(controls["RuntimeMaxUSec"]) != 180000000
                           or int(controls["TimeoutStopUSec"]) != 15000000):
        raise RuntimeError("daemon lifetime or placement mismatch")
    return UnitIdentity(name, invocation, cgroup, job)


def cgroup_path(value):
    if not value.startswith("/") or ".." in Path(value).parts:
        raise RuntimeError("invalid cgroup path")
    path = CGROUP / value.lstrip("/")
    if path.resolve() != path:
        raise RuntimeError("cgroup path resolves elsewhere")
    return path


def bounded_parent(value):
    leaf = cgroup_path(value)
    rows = []
    for path in [leaf, *leaf.parents]:
        if path == CGROUP.parent:
            break
        if path == CGROUP or CGROUP in path.parents:
            rows.append({"path": str(path), **{
                key: (path / key).read_text().strip() if present(path / key) else None
                for key in ("cpu.max", "memory.max", "memory.swap.max", "pids.max",
                            "cgroup.controllers", "cgroup.subtree_control")
            }})
    exact = rows[0]
    quota, period = exact["cpu.max"].split()
    if (quota == "max" or int(quota) > 2 * int(period)
            or exact["memory.max"] == "max" or int(exact["memory.max"]) > 4294967296
            or exact["memory.swap.max"] != "0" or exact["pids.max"] == "max"
            or int(exact["pids.max"]) > 512):
        raise RuntimeError("actual slice bounds exceed allocation")
    if not {"cpu", "memory", "pids"} <= set(exact["cgroup.controllers"].split()):
        raise RuntimeError("missing effective controllers")
    return rows


def process_identity(pid, parent):
    root = PROC / str(pid)
    before = (root / "stat").read_text().rsplit(")", 1)[1].split()
    cgroup = (root / "cgroup").read_text().strip()
    if not cgroup.startswith("0::"):
        raise RuntimeError("not unified cgroup v2")
    cgroup = cgroup[3:]
    if cgroup != parent and not cgroup.startswith(parent + "/"):
        raise RuntimeError("observed process escaped owned slice")
    result = ProcessIdentity(
        pid, int(before[19]), int(before[1]), cgroup,
        tuple(x.decode() for x in (root / "cmdline").read_bytes().split(b"\0") if x),
        tuple((name, os.readlink(root / "ns" / name)) for name in ("mnt", "net", "user")),
    )
    after = (root / "stat").read_text().rsplit(")", 1)[1].split()
    if (before[19] != after[19]
            or (root / "cgroup").read_text().strip() != "0::" + cgroup):
        raise RuntimeError("PID or cgroup changed during observation")
    return result


def managed_containerd(config_bytes, argv):
    config = tomllib.loads(config_bytes.decode())
    expected = {
        "root": str(P / "data/containerd/daemon"),
        "state": str(R / "exec/containerd/daemon"),
    }
    if any(config.get(key) != value for key, value in expected.items()):
        raise RuntimeError("managed containerd storage mismatch")
    if (config.get("grpc", {}).get("address") != str(R / "exec/containerd/containerd.sock")
            or config.get("debug", {}).get("address") != str(R / "exec/containerd/containerd-debug.sock")
            or tuple(argv) != ("/usr/bin/containerd", "--config", str(R / "exec/containerd/containerd.toml"))):
        raise RuntimeError("managed containerd socket or argv mismatch")
    return config


def check_info(info):
    security = info.get("SecurityOptions", [])
    driver_status = dict(info.get("DriverStatus", []))
    if (info.get("ServerVersion") != "29.9.0" or not info.get("ID")
            or info.get("DockerRootDir") != str(P / "data")
            or info.get("Containers") != 0 or info.get("Images") != 0
            or info.get("CgroupDriver") != "systemd" or info.get("CgroupVersion") != "2"
            or driver_status.get("driver-type") != "io.containerd.snapshotter.v1"
            or "name=rootless" not in security
            or "name=seccomp,profile=builtin" not in security
            or "name=cgroupns" not in security):
        raise RuntimeError("private native zero-object Info mismatch")
    return info["ID"]


def start_owned(name):
    if name not in (SLICE, DAEMON):
        raise RuntimeError("unit outside daemon-only scope")
    props = slice_properties() if name == SLICE else daemon_properties()
    job = owned_job(user_bus(), name, lambda manager: manager.StartTransientUnit(
        name, "fail", props, dbus.Array([], signature="(sa(sv))"), timeout=5))
    bus = user_bus()
    try:
        return identity(bus, name, job)
    finally:
        bus.close()


def stop_owned(owned):
    if owned.name not in (SLICE, DAEMON, INFO):
        raise RuntimeError("unit outside daemon-only scope")
    bus = user_bus()
    try:
        current = identity(bus, owned.name, owned.job)
        if current.invocation != owned.invocation or current.cgroup != owned.cgroup:
            raise RuntimeError("unit invocation changed before stop")
    finally:
        bus.close()
    return owned_job(user_bus(), owned.name,
                     lambda manager: manager.StopUnit(owned.name, "fail", timeout=5), wait_seconds=20)


def stopped_unit(owned):
    bus = user_bus()
    try:
        manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                               "/org/freedesktop/systemd1"), MANAGER)
        if any(str(row[1]) == owned.name for row in manager.ListJobs(timeout=5)):
            raise RuntimeError("owned unit still has a job")
        try:
            unit = properties(bus, owned.name, UNIT)
        except dbus.DBusException as error:
            if error.get_dbus_name() != "org.freedesktop.systemd1.NoSuchUnit":
                raise
            return {"name": owned.name, "state": "absent"}
        invocation = bytes(unit["InvocationID"])
        if (unit["ActiveState"] != "inactive" or unit["SubState"] != "dead"
                or int(unit["Job"][0]) != 0 or str(unit["Job"][1]) != "/"
                or invocation not in (owned.invocation, b"", bytes(16))):
            raise RuntimeError("owned unit lacks exact terminal state")
        if owned.name != SLICE:
            service = properties(bus, owned.name, SERVICE)
            if int(service["MainPID"]) != 0:
                raise RuntimeError("owned service retains a main PID")
        return {"name": owned.name, "state": "inactive/dead", "invocation": invocation.hex()}
    finally:
        bus.close()


def check_stopped_objects(parent, processes):
    path = cgroup_path(parent.cgroup)
    if present(path) and "populated 0" not in (path / "cgroup.events").read_text().splitlines():
        raise RuntimeError("owned cgroup remains populated")
    for process in processes:
        try:
            starttime = int((PROC / str(process.pid) / "stat").read_text().rsplit(")", 1)[1].split()[19])
        except FileNotFoundError:
            continue
        if starttime == process.starttime:
            raise RuntimeError("owned process remains alive")
    for socket in (R / "docker.sock", R / "exec/containerd/containerd.sock",
                   R / "exec/containerd/containerd-debug.sock", R / "rootlesskit/api.sock"):
        if present(socket):
            raise RuntimeError(f"retained socket needs exact reconciliation: {socket}")


def pending_receipt(path, source_identity, owner, boot_id):
    body = json.dumps({
        "status": "pending", "nonce": NONCE, "base": BASE,
        "source": source_identity, "owner": dataclasses.asdict(owner), "boot": boot_id,
        "slice": SLICE, "daemon": DAEMON, "persistent": str(P), "runtime": str(R),
        "endpoint": URI, "proposal_seconds": 300,
        "reference_scope": "owned-actors-and-references", "outside_holders": "unmeasured",
    }, sort_keys=True).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(body).hexdigest()


def info_properties():
    argv = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", f"HOME={P}/home",
            f"DOCKER_CONFIG={P}/docker-config", "/usr/bin/docker", "--config",
            str(P / "docker-config"), "--host", URI, "info", "--format", "{{json .}}"]
    return dbus.Array([
        ("Description", dbus.String(f"goal330 {NONCE}")),
        ("Type", dbus.String("oneshot")),
        ("RemainAfterExit", dbus.Boolean(True)),
        ("Slice", dbus.String(SLICE)),
        ("Delegate", dbus.Boolean(False)),
        ("Restart", dbus.String("no")),
        ("KillMode", dbus.String("control-group")),
        ("TimeoutStartUSec", dbus.UInt64(10000000)),
        ("TimeoutStopUSec", dbus.UInt64(5000000)),
        ("StandardOutputFile", dbus.String(str(P / "info.json"))),
        ("StandardErrorFile", dbus.String(str(P / "info.stderr"))),
        ("ExecStart", dbus.Array([(argv[0], argv, False)], signature="(sasb)")),
    ], signature="(sv)")


def create_private_files():
    for path in (P, R):
        if any(parent.is_symlink() for parent in path.parents):
            raise RuntimeError("private ancestry contains a symlink")
        path.mkdir(mode=0o700)
    for name in ("home", "config", "xdgdata", "cache", "tmp", "docker-config"):
        (P / name).mkdir(mode=0o700)
    (R / "xdg").mkdir(mode=0o700)
    for path, body in ((P / "daemon.json", json.dumps(daemon_config())),
                       (P / "docker-config/config.json", "{}")):
        with path.open("x") as output:
            output.write(body + "\n")
    return {str(path): [path.stat().st_dev, path.stat().st_ino] for path in (P, R)}


def actors(parent):
    bus = user_bus()
    try:
        manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                               "/org/freedesktop/systemd1"), MANAGER)
        pids = manager.GetUnitProcesses(SLICE, timeout=5)
    finally:
        bus.close()
    result = []
    details = []
    for _group, pid, _name in pids:
        process = process_identity(int(pid), parent.cgroup)
        root = PROC / str(pid)
        descriptors = {entry.name: os.readlink(entry) for entry in (root / "fd").iterdir()}
        sockets = {value[8:-1] for value in descriptors.values() if value.startswith("socket:[")}
        listeners = {}
        for name in ("unix", "tcp", "tcp6", "udp", "udp6"):
            column = 6 if name == "unix" else 9
            listeners[name] = [line for line in (root / "net" / name).read_text().splitlines()[1:]
                               if len(line.split()) > column and line.split()[column] in sockets]
        result.append(process)
        details.append({
            "identity": dataclasses.asdict(process), "uid": root.stat().st_uid,
            "status": (root / "status").read_text(),
            "uid_map": (root / "uid_map").read_text(),
            "gid_map": (root / "gid_map").read_text(),
            "context": (root / "attr/current").read_text(),
            "mountinfo": (root / "mountinfo").read_text(),
            "listeners": listeners,
            "fds": descriptors,
        })
        if process_identity(int(pid), parent.cgroup) != process:
            raise RuntimeError("owned actor changed during metadata observation")
    if not result:
        raise RuntimeError("no daemon actors observed")
    return result, details


def host_state():
    enforce = Path("/sys/fs/selinux/enforce").read_text().strip()
    if enforce != "1":
        raise RuntimeError("host SELinux is not Enforcing")
    files = [Path("/proc/sys/net/ipv4/ip_forward"),
             Path("/proc/sys/net/ipv6/conf/all/forwarding"),
             Path("/etc/subuid"), Path("/etc/subgid"),
             Path("/etc/docker/daemon.json"), Path("/usr/lib/systemd/system/docker.service"),
             Path("/usr/lib/systemd/user/docker.service")]
    listeners = {}
    for name in ("tcp", "tcp6"):
        lines = Path(f"/proc/self/net/{name}").read_text().splitlines()[1:]
        listeners[name] = sorted(line.split()[1] for line in lines if line.split()[3] == "0A")
    return {"enforce": enforce, "run_label": os.getxattr("/run", "security.selinux").hex(),
            "listeners": listeners,
            "files": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                      if present(path) else None for path in files}}


def detached_netns(parent, processes):
    child_pid = int((R / "rootlesskit/child_pid").read_text())
    child = next((process for process in processes if process.pid == child_pid), None)
    if child is None or process_identity(child_pid, parent.cgroup) != child:
        raise RuntimeError("detached netns child is not an exact owned actor")
    path = R / "rootlesskit/netns"
    subject = PROC / str(child_pid) / "root" / path.relative_to("/")
    before = subject.stat()
    mounts = (PROC / str(child_pid) / "mountinfo").read_text()
    matches = [line for line in mounts.splitlines() if line.split()[4] == str(path)]
    if len(matches) != 1:
        raise RuntimeError("detached netns lacks its exact owned mount")
    fields = matches[0].split()
    if (fields[2] != f"{os.major(before.st_dev)}:{os.minor(before.st_dev)}"
            or fields[3] != f"net:[{before.st_ino}]"
            or fields[fields.index("-") + 1] != "nsfs"):
        raise RuntimeError("detached netns stat and nsfs mount identity mismatch")
    after = subject.stat()
    if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or process_identity(child_pid, parent.cgroup) != child):
        raise RuntimeError("detached netns owner or identity changed")
    return DetachedNetns(child, str(path), before.st_dev, before.st_ino, matches[0])


def owned_references_closed(parent, processes, detached, owner, observer_mounts, boot):
    check_stopped_objects(parent, processes)
    if (PROC / "sys/kernel/random/boot_id").read_text().strip() != boot:
        raise RuntimeError("boot changed during owned closure")
    if process_identity(owner.pid, owner.cgroup) != owner:
        raise RuntimeError("outside observer identity changed")
    mounts = (PROC / "self/mountinfo").read_text()
    if mounts != observer_mounts or str(P) in mounts or str(R) in mounts:
        raise RuntimeError("observer mount table changed or retains a private path")
    if any(line.split()[3] == f"net:[{detached.inode}]"
           and line.split()[2] == f"{os.major(detached.device)}:{os.minor(detached.device)}"
           for line in mounts.splitlines()):
        raise RuntimeError("detached netns was exported into observer mount table")
    private = {value for process in processes for _, value in process.namespaces}
    private -= {value for _, value in owner.namespaces}
    private.add(f"net:[{detached.inode}]")
    with os.scandir(PROC / "self/fd") as entries:
        if any(os.readlink(entry.path) in private for entry in entries):
            raise RuntimeError("observer retains an owned private namespace descriptor")
    if process_identity(owner.pid, owner.cgroup) != owner:
        raise RuntimeError("outside observer changed during closure")
    return {"contract": "owned-actors-and-references", "outside_holders": "unmeasured",
            "assumption": "unrelated host actors do not acquire or receive namespace references",
            "observed_namespaces": sorted({value for process in processes
                                            for _, value in process.namespaces}),
            "detached_netns": dataclasses.asdict(detached), "observer_mounts_equal": True,
            "observer_private_namespace_fds": "none",
            "observer_mounts_after": mounts}


def append_observation(path, value):
    with path.open("x") as output:
        json.dump(value, output, sort_keys=True, default=lambda obj: obj.hex() if isinstance(obj, bytes)
                  else dataclasses.asdict(obj))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def daemon_only():
    os.umask(0o077)
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(300)
    deadline = time.monotonic() + 300
    lock = os.open("/tmp/vespiary-heavy-validation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    own_group = Path("/proc/self/cgroup").read_text().strip().removeprefix("0::")
    owner = process_identity(os.getpid(), own_group)
    boot = (PROC / "sys/kernel/random/boot_id").read_text().strip()
    source = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in (Path(__file__).resolve().with_name(name) for name in
                           ("daemon_bootstrap.py", "systemd_job.py", "test_daemon_bootstrap.py",
                            "test_systemd_job.py"))}
    pending_receipt(RECEIPT, source, owner, boot)
    try:
        before = host_state()
        observer_mounts = (PROC / "self/mountinfo").read_text()
        if os.getuid() != 1000 or os.getgid() != 1000:
            raise RuntimeError("unexpected host user identity")
        for path in (P, R):
            if present(path):
                raise RuntimeError("private path already exists")
        bus = user_bus()
        try:
            manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1",
                                                   "/org/freedesktop/systemd1"), MANAGER)
            loaded = {str(row[0]) for row in manager.ListUnits(timeout=5)}
            jobs = {str(row[1]) for row in manager.ListJobs(timeout=5)}
            if {SLICE, DAEMON, INFO} & (loaded | jobs):
                raise RuntimeError("owned unit name already exists")
        finally:
            bus.close()
        parent = start_owned(SLICE)
        limits = bounded_parent(parent.cgroup)
        paths = create_private_files()
        append_observation(RECEIPT.with_suffix(".parent.json"),
                           {"parent": parent, "limits": limits, "paths": paths, "host": before})
        if time.monotonic() > deadline - 210:
            raise RuntimeError("insufficient finite daemon lifetime remaining")
        daemon = start_owned(DAEMON)
        append_observation(RECEIPT.with_suffix(".daemon.json"), {"daemon": daemon})
        ready = min(deadline - 60, time.monotonic() + 30)
        while not present(R / "docker.sock"):
            if time.monotonic() >= ready:
                raise RuntimeError("daemon socket readiness deadline")
            time.sleep(0.1)
        if not stat.S_ISSOCK((R / "docker.sock").lstat().st_mode):
            raise RuntimeError("daemon endpoint is not a socket")
        job = owned_job(user_bus(), INFO, lambda manager: manager.StartTransientUnit(
            INFO, "fail", info_properties(), dbus.Array([], signature="(sa(sv))"), timeout=5))
        bus = user_bus()
        try:
            info_unit = identity(bus, INFO, job)
        finally:
            bus.close()
        daemon_id = check_info(json.loads((P / "info.json").read_text()))
        processes, details = actors(parent)
        detached = detached_netns(parent, processes)
        executables = {Path(process.argv[0]).name for process in processes if process.argv}
        if not {"rootlesskit", "dockerd", "containerd", "pasta"} <= executables:
            raise RuntimeError("native rootless daemon ancestry is incomplete")
        containerd_pid = int((R / "exec/containerd/containerd.pid").read_text())
        containerd = next(process for process in processes if process.pid == containerd_pid)
        config = (R / "exec/containerd/containerd.toml").read_bytes()
        managed_containerd(config, containerd.argv)
        append_observation(RECEIPT.with_suffix(".observation.json"), {
            "daemon_id": daemon_id, "info_unit": info_unit, "actors": details,
            "detached_netns": detached, "observer_mounts_before": observer_mounts,
            "containerd_config": config.decode(), "limits": bounded_parent(parent.cgroup),
            "socket_label": os.getxattr(R / "docker.sock", "security.selinux").hex(),
        })
        if time.monotonic() > deadline - 45:
            raise RuntimeError("insufficient teardown time")
        info_stop = stop_owned(info_unit)
        daemon_stop = stop_owned(daemon)
        terminal = [stopped_unit(unit) for unit in (info_unit, daemon)]
        closure = owned_references_closed(parent, processes, detached, owner, observer_mounts, boot)
        if before != host_state():
            raise RuntimeError("host state changed")
        if any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest
               for path, digest in source.items()):
            raise RuntimeError("source changed during attempt")
        append_observation(RECEIPT.with_suffix(".stopped.json"),
                           {"info_job": info_stop, "daemon_job": daemon_stop,
                            "terminal_units": terminal, "owned_reference_closure": closure})
        parent_stop = stop_owned(parent)
        parent_terminal = stopped_unit(parent)
        check_stopped_objects(parent, processes)
        if time.monotonic() > deadline:
            raise RuntimeError("attempt exceeded 300 seconds")
        files = []
        for root in (P, R):
            for path in (root, *root.rglob("*")):
                metadata = path.lstat()
                files.append({"path": str(path), "device": metadata.st_dev, "inode": metadata.st_ino,
                              "uid": metadata.st_uid, "gid": metadata.st_gid, "mode": metadata.st_mode})
        append_observation(RECEIPT.with_suffix(".closed.json"),
                           {"status": "closed", "source": source, "slice_stop_job": parent_stop,
                            "slice_terminal": parent_terminal, "owned_reference_closure": closure,
                            "retained_owned_files": files})
    except BaseException as error:
        append_observation(RECEIPT.with_suffix(".failed.json"),
                           {"status": "failed-or-unknown", "error": repr(error), "source": source})
        raise
    os.close(lock)
    signal.alarm(0)


if __name__ == "__main__":
    daemon_only()
