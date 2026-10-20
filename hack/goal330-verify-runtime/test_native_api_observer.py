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
import json
import os
from pathlib import Path
import tempfile
import signal
import subprocess
import time
import unittest
from unittest.mock import Mock, PropertyMock, patch

import dbus

import native_api_observer as native
import native_python_entry as entry
from systemd_job import owned_job

native.setup_native()


class NativeObserverTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.proc = self.root / "proc"
        self.cg = self.root / "cgroup"
        self.reviews = self.root / "reviews"
        self.reviews.mkdir()
        self.attempt = native.Attempt("00000000000000000000000000000001")
        for target, value in (("PROC", self.proc), ("CGROUP", self.cg), ("REVIEWS", self.reviews)):
            self.enterContext(patch.object(native, target, value))
        self.enterContext(patch.object(native.Attempt, "p", new_callable=PropertyMock,
                                      return_value=self.root / "persistent"))
        self.enterContext(patch.object(native.Attempt, "r", new_callable=PropertyMock,
                                      return_value=self.root / "runtime"))
        self.boot = "fixture-boot"
        boot = self.proc / "sys/kernel/random/boot_id"
        boot.parent.mkdir(parents=True)
        boot.write_text(self.boot)
        (self.proc / "self").mkdir()
        (self.proc / "self/mountinfo").write_text("fixture observer mount\n")
        (self.proc / "self/exe").symlink_to("/usr/bin/python3")
        self.parent = native.UnitIdentity(self.boot, self.attempt.units[0], b"p" * 16,
                                            "/fixture.slice", "/job/1")
        self.daemon = native.UnitIdentity(self.boot, self.attempt.units[1], b"d" * 16,
                                            "/fixture.slice/daemon.service", "/job/2")
        self.owner = native.ProcessIdentity(self.boot, "outside-holder", b"", "/outside", "",
                                           77, 777, 5, 77, ("python3",))
        self.api = native.UnitIdentity(self.boot, self.attempt.units[3], b"a" * 16, "", "/job/4")
        self.info = dataclasses.replace(self.api, unit=self.attempt.units[2], invocation=b"i" * 16,
                                        job="/job/3")
        argv = ("rootlesskit", f"--state-dir={self.attempt.r}/rootlesskit", "--net=pasta",
                "--mtu=65520", "--slirp4netns-sandbox=auto", "--slirp4netns-seccomp=auto",
                "--disable-host-loopback", "--port-driver=implicit", "--copy-up=/etc",
                "--copy-up=/run", "--propagation=rslave", "--detach-netns",
                "/usr/bin/dockerd-rootless.sh", f"--config-file={self.attempt.p}/daemon.json", "--group=0")
        self.parent_actor = native.ProcessIdentity(**dataclasses.asdict(self.daemon), pid=101, starttime=1001, ppid=5, pgrp=101, argv=argv)
        self.child = dataclasses.replace(self.parent_actor, pid=102, starttime=1002, ppid=101, argv=("exe",))
        self.docker = dataclasses.replace(self.parent_actor, pid=103, starttime=1003, ppid=102,
                                          argv=("dockerd", f"--config-file={self.attempt.p}/daemon.json", "--group=0"))
        self.containerd = dataclasses.replace(self.parent_actor, pid=104, starttime=1004, ppid=103,
                                              pgrp=104, argv=("/usr/bin/containerd", "--config",
                                                            str(self.attempt.r / "exec/containerd/containerd.toml")))
        self.pasta = dataclasses.replace(self.parent_actor, pid=105, starttime=1005, ppid=5,
                                         pgrp=105, argv=("/usr/bin/pasta.avx2",))
        self.actors = (self.parent_actor, self.child, self.docker, self.containerd, self.pasta)
        for actor in (*self.actors, self.owner):
            self.write_process(actor)
        self.host = {"selected-host-fixture": "unchanged"}
        self.enterContext(patch.object(native, "host_state", return_value=self.host))
        self.enterContext(patch.object(native, "properties", return_value={"MainPID": 101}))
        self.enterContext(patch.object(native, "user_bus", return_value=Mock()))
        self.source_file = self.root / "frozen-input"
        self.source_file.write_bytes(b"fixed")
        self.source = native.digest_map((self.source_file,))
        self.mutations = []
        self.receipts = []

    def write_process(self, actor):
        root = self.proc / str(actor.pid)
        root.mkdir(exist_ok=True)
        fields = ["0"] * 22
        fields[0], fields[1], fields[2], fields[19] = "S", str(actor.ppid), str(actor.pgrp), str(actor.starttime)
        (root / "stat").write_text(f"{actor.pid} (fixture) " + " ".join(fields))
        (root / "cgroup").write_text("0::" + actor.cgroup)
        (root / "cmdline").write_bytes(b"\0".join(arg.encode() for arg in actor.argv) + b"\0")

    def api_value(self):
        return {"apiVersion": "1.1.3", "version": "3.2.0", "stateDir": str(self.attempt.r / "rootlesskit"),
                "childPID": 102, "networkDriver": {"driver": "pasta", "dynamicChildIP": False}}

    def docker_value(self):
        return {"ServerVersion": "29.9.0", "ID": "fixture-daemon-id", "DockerRootDir": str(self.attempt.p / "data"),
                "Containers": 0, "Images": 0, "CgroupDriver": "systemd", "CgroupVersion": "2",
                "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]],
                "SecurityOptions": ["name=rootless", "name=seccomp,profile=builtin", "name=cgroupns"],
                "Containerd": {"Address": str(self.attempt.sockets[2])}}

    def metadata(self):
        (self.attempt.r / "rootlesskit").mkdir(parents=True, exist_ok=True)
        (self.attempt.r / "rootlesskit/child_pid").write_text("102")
        (self.attempt.r / "docker.pid").write_text("103")
        directory = self.attempt.r / "exec/containerd"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "containerd.pid").write_text("104")
        (directory / "containerd.toml").write_text(
            f'root = "{self.attempt.p}/data/containerd/daemon"\n'
            f'state = "{self.attempt.r}/exec/containerd/daemon"\n'
            f'[grpc]\naddress = "{self.attempt.sockets[2]}"\n'
            f'[debug]\naddress = "{self.attempt.sockets[3]}"\n')
        for path in self.attempt.sockets:
            path.touch()

    def workflow(self, fault=None):
        def receipt(path, value):
            self.receipts.append((path.suffixes[-2], value))

        def start(_attempt, unit, observation):
            self.mutations.append(("start", unit))
            observation.intents.append(unit)
            bound = next(item for item in (self.parent, self.daemon, self.info, self.api) if item.unit == unit)
            if fault == "timeout" and unit == self.api.unit:
                raise TimeoutError("native five-second request timeout")
            observation.units.append(bound)
            if unit == self.parent.unit:
                return self.parent
            if unit == self.daemon.unit:
                self.metadata()
                return self.daemon
            if unit == self.info.unit:
                (self.attempt.p / "info.json").write_text(json.dumps(self.docker_value()))
                observation.clients.append({"join_error": None, "buffers": {
                    "info.json": {"raw": json.dumps(self.docker_value()).encode().hex()}}})
                return self.info
            if unit == self.api.unit:
                value = self.api_value()
                if fault == "mismatch":
                    value["childPID"] = 999
                body = json.dumps(value).encode()
                if fault == "malformed":
                    body = b'{"childPID":'
                if fault == "oversize":
                    body = b"x" * (native.MAX_RESPONSE + 1)
                (self.attempt.p / "rootlesskit-info.json").write_bytes(body)
                (self.attempt.p / "rootlesskit-status.json").write_bytes(b"302" if fault == "redirect" else b"200")
                observation.clients.append({"join_error": None, "buffers": {
                    "rootlesskit-info.json": {"raw": body.hex()},
                    "rootlesskit-status.json": {"raw": (b"302" if fault == "redirect" else b"200").hex()}}})
                if fault == "pid-reuse":
                    self.write_process(dataclasses.replace(self.child, starttime=9000))
                if fault == "source":
                    self.source_file.write_bytes(b"changed")
                if fault == "boot":
                    (self.proc / "sys/kernel/random/boot_id").write_text("changed")
                if fault == "host":
                    self.host["selected-host-fixture"] = "changed"
                if fault == "mount":
                    (self.proc / "self/mountinfo").write_text("changed")
                return self.api
            raise AssertionError(unit)

        def stop(_attempt, unit):
            self.mutations.append(("stop", unit.unit))
            if fault in ("lost-job", "failed-job", "unrelated-job"):
                raise RuntimeError("unknown or failed owned job")
            if fault == "invocation" and unit.unit == self.daemon.unit:
                raise RuntimeError("changed native invocation")
            return "/job/stop"

        def closed(_attempt, _parent, _actors):
            if fault in ("populated", "stale-socket"):
                raise RuntimeError(fault)

        manager = Mock()
        manager.ListUnits.return_value = []
        manager.ListJobs.return_value = []
        identity = lambda _attempt, _unit, _job: dataclasses.replace(
            self.daemon, invocation=b"x" * 16) if fault == "invocation" else self.daemon
        host_before = dict(self.host)
        with patch.object(native, "user_bus", return_value=Mock()), patch.object(
            native.dbus, "Interface", return_value=manager
        ), patch.object(native, "append_receipt", side_effect=receipt), patch.object(
            native, "bounded_parent", return_value=[{"fixture": "bounded before birth"}]
        ), patch.object(native.Attempt, "start", start), patch.object(native.Attempt, "stop", stop), patch.object(
            native.Attempt, "identity", identity
        ), patch.object(native.Attempt, "actors", side_effect=PermissionError("required metadata")
                        if fault == "denial" else None, return_value=self.actors), patch.object(
            native.Attempt, "socket_identity", return_value=("fixture socket inodes",)
        ), patch.object(native.Attempt, "closed_objects", closed), patch.object(
            native.Attempt, "terminal", return_value={"state": "inactive/dead"}
        ), patch.object(native, "host_state", side_effect=lambda: dict(self.host)):
            with patch.object(native.signal, "signal"), patch.object(native.signal, "alarm"):
                status = self.attempt.finite(self.owner, self.source)
            result = self.receipts[-1][1]
            self.assertEqual(result["status"], status)
            if fault:
                self.assertNotEqual(status, "qualified-and-closed")
                if fault in ("denial", "invocation"):
                    self.assertNotIn(("start", self.api.unit), self.mutations)
                if fault in ("timeout", "invocation", "populated", "stale-socket", "boot", "mount",
                             "lost-job", "failed-job", "unrelated-job"):
                    self.assertEqual(status, "retained-unknown")
                    self.assertNotIn(("stop", self.parent.unit), self.mutations)
                else:
                    self.assertEqual(status, "failed-but-closed")
                first_stop = next((index for index, item in enumerate(self.mutations) if item[0] == "stop"), len(self.mutations))
                self.assertFalse(any(kind == "start" for kind, _unit in self.mutations[first_stop:]))
            else:
                self.assertEqual(status, "qualified-and-closed")
                self.assertEqual(self.mutations, [("start", item) for item in self.attempt.units] +
                                 [("stop", item) for item in (self.api.unit, self.info.unit,
                                                              self.daemon.unit, self.parent.unit)])
                closure = result["closure"]
                self.assertEqual(closure["outside_holders"], "unmeasured")
                self.assertEqual(closure["detached_namespace_identity"], "unmeasured")
                self.assertNotIn("owned_reference_closure", result)
                self.assertEqual(self.host, host_before)

    def test_normal_observer_and_paired_refusals(self):
        self.workflow()

    def test_api_and_identity_refuse_before_later_mutation(self):
        for fault in ("timeout", "malformed", "oversize", "mismatch", "redirect", "pid-reuse",
                      "invocation", "denial", "source", "boot", "host", "mount", "populated",
                      "stale-socket", "lost-job", "failed-job", "unrelated-job"):
            with self.subTest(fault=fault):
                case = NativeObserverTest(methodName="test_normal_observer_and_paired_refusals")
                case.setUp()
                try:
                    case.workflow(fault)
                finally:
                    case.doCleanups()

    def test_strict_response_rejects_duplicate_trailing_nonfinite_and_wrong_shapes(self):
        self.assertEqual(native.strict_json(b'{"childPID":102}'), {"childPID": 102})
        for body in (b'{"x":1,"x":2}', b'{}{}', b'{"x":NaN}', b'\xff', b"x" * 65537):
            with self.subTest(body=body[:30]), self.assertRaises((ValueError, RuntimeError)):
                native.strict_json(body)
        self.metadata()
        self.assertEqual(self.attempt.rootlesskit(self.daemon, self.actors, self.api_value())[1], self.child)
        for field, value in (("childPID", True), ("stateDir", "/shared"), ("version", "wrong"),
                             ("apiVersion", "wrong"), ("portDriver", {"driver": "implicit"}),
                             ("networkDriver", {"driver": "other"})):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.attempt.rootlesskit(self.daemon, self.actors, {**self.api_value(), field: value})

    def test_managed_containerd_metadata_is_exact(self):
        self.metadata()
        self.assertEqual(self.attempt.managed_containerd(self.actors)["identity"], self.containerd)
        path = self.attempt.r / "exec/containerd/containerd.toml"
        good = path.read_text()
        for old, new in (("data/containerd/daemon", "other"), ("exec/containerd/daemon", "other"),
                         ("containerd.sock", "shared.sock"), ("containerd-debug.sock", "shared-debug.sock")):
            with self.subTest(old=old), self.assertRaises(RuntimeError):
                path.write_text(good.replace(old, new))
                self.attempt.managed_containerd(self.actors)
        path.write_text(good)
        for pidfile in (self.attempt.r / "exec/containerd/containerd.pid", self.attempt.r / "docker.pid"):
            good_pid = pidfile.read_text()
            pidfile.write_text("999")
            with self.assertRaises(RuntimeError):
                self.attempt.managed_containerd(self.actors)
            pidfile.write_text(good_pid)
        wrong = dataclasses.replace(self.containerd, argv=("/usr/bin/containerd", "--address", "/shared"))
        with self.assertRaises(RuntimeError):
            self.attempt.managed_containerd(tuple(wrong if actor.pid == wrong.pid else actor for actor in self.actors))

    def test_docker_info_preserves_zero_objects_endpoint_and_defaults(self):
        self.assertEqual(self.attempt.docker_info(self.docker_value()), "fixture-daemon-id")
        for field, value in (("Containers", 1), ("Images", False), ("DockerRootDir", "/shared"),
                             ("SecurityOptions", ["name=rootless"]),
                             ("Containerd", {"Address": "/shared.sock"})):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.attempt.docker_info({**self.docker_value(), field: value})

    def test_required_metadata_denial_escape_and_pid_reuse(self):
        self.assertEqual(native.process_identity(self.child.pid, self.child), self.child)
        escaped = dataclasses.replace(self.child, cgroup="/escaped")
        self.write_process(escaped)
        with self.assertRaisesRegex(RuntimeError, "escaped"):
            native.process_identity(self.child.pid, self.child)
        self.write_process(self.child)
        original = native.read_bounded
        def denied(path, limit):
            if path == self.proc / str(self.child.pid) / "cmdline":
                raise PermissionError("required ordinary metadata")
            return original(path, limit)
        with patch.object(native, "read_bounded", denied), self.assertRaises(PermissionError):
            native.process_identity(self.child.pid, self.child)
        self.write_process(dataclasses.replace(self.child, starttime=2222))
        self.assertNotEqual(native.process_identity(self.child.pid, self.child), self.child)

    def test_positive_closure_requires_cgroup_process_group_and_socket_absence(self):
        group = self.cg / self.parent.cgroup.lstrip("/")
        group.mkdir(parents=True)
        events = group / "cgroup.events"
        events.write_text("populated 0\n")
        manager = Mock()
        manager.GetUnitProcesses.return_value = []
        gone = dataclasses.replace(self.child, pid=999, pgrp=999)
        with patch.object(native, "user_bus", return_value=Mock()), patch.object(
            native.dbus, "Interface", return_value=manager
        ), patch.object(native.os, "killpg", side_effect=ProcessLookupError):
            self.attempt.closed_objects(self.parent, (gone,))
            events.write_text("populated 1\n")
            with self.assertRaisesRegex(RuntimeError, "descendant"):
                self.attempt.closed_objects(self.parent, (gone,))
            events.write_text("populated 0\n")
            with self.assertRaisesRegex(RuntimeError, "PID/start"):
                self.attempt.closed_objects(self.parent, (self.child,))
            self.write_process(dataclasses.replace(self.child, starttime=2222))
            self.attempt.closed_objects(self.parent, (self.child,))
            with patch.object(native.os, "killpg", return_value=None), self.assertRaisesRegex(RuntimeError, "group"):
                self.attempt.closed_objects(self.parent, (gone,))
            self.attempt.r.mkdir()
            self.attempt.sockets[0].touch()
            with self.assertRaisesRegex(RuntimeError, "stale"):
                self.attempt.closed_objects(self.parent, (gone,))
            manager.GetUnitProcesses.return_value = [("/escaped", 999, "fixture")]
            with self.assertRaisesRegex(RuntimeError, "inventory"):
                self.attempt.closed_objects(self.parent, (gone,))

    def test_bounds_refuse_before_daemon_birth(self):
        group = self.cg / self.parent.cgroup.lstrip("/")
        group.mkdir(parents=True)
        good = {"cpu.max": "200000 100000", "memory.max": "4294967296", "memory.swap.max": "0",
                "pids.max": "512", "cgroup.controllers": "cpu memory pids", "cgroup.subtree_control": "+cpu +memory +pids"}
        for name, value in good.items():
            (group / name).write_text(value)
        self.assertEqual(native.bounded_parent(self.parent.cgroup)[0]["pids.max"], "512")
        for name, value in (("cpu.max", "300000 100000"), ("memory.max", "4294967297"),
                             ("memory.swap.max", "1"), ("pids.max", "513")):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "pre-birth"):
                (group / name).write_text(value)
                native.bounded_parent(self.parent.cgroup)
            (group / name).write_text(good[name])

    def test_changed_invocation_refuses_stop(self):
        with patch.object(native.Attempt, "identity", return_value=self.daemon), patch.object(native, "owned_job") as job:
            self.assertEqual(self.attempt.stop(self.daemon), job.return_value)
        with patch.object(native.Attempt, "identity", return_value=dataclasses.replace(self.daemon, invocation=b"x" * 16)), patch.object(native, "owned_job") as job:
            with self.assertRaisesRegex(RuntimeError, "changed"):
                self.attempt.stop(self.daemon)
            job.assert_not_called()

    def test_native_lifetimes_and_single_bounded_standard_client(self):
        daemon = dict(self.attempt.unit_properties(self.daemon.unit))
        self.assertEqual(int(daemon["RuntimeMaxUSec"]), 180000000)
        self.assertEqual(int(daemon["TimeoutStopUSec"]), 15000000)
        self.assertEqual(int(daemon["RuntimeRandomizedExtraUSec"]), 0)
        api = dict(self.attempt.unit_properties(self.api.unit))
        self.assertEqual(api["Slice"], self.parent.unit)
        self.assertFalse(api["Delegate"])
        self.assertEqual(int(api["LimitFSIZE"]), 65536)
        self.assertEqual(int(api["LimitFSIZESoft"]), 65536)
        argv = self.attempt.api_argv()
        self.assertEqual(argv.count("http://rootlesskit/v1/info"), 1)
        for option, value in (("--max-time", "5"), ("--max-filesize", "65536"),
                              ("--max-redirs", "0"), ("--retry", "0"), ("--proto", "=http"),
                              ("--unix-socket", str(self.attempt.r / "rootlesskit/api.sock"))):
            self.assertEqual(argv[argv.index(option) + 1], value)
        self.assertNotIn("--location", argv)
        self.assertEqual(argv[argv.index("/usr/bin/curl") + 1], "--disable")

    def test_consumed_or_missing_identity_refuses(self):
        for nonce in (None, "", "b7a6306f20fabfaab02a29eaecf04531", "18ec13b3d43234b8ab4f79fbc49e0c1d"):
            with self.subTest(nonce=nonce), self.assertRaisesRegex(RuntimeError, "root must"):
                native.Attempt(nonce)


class NativeJobRefusalTest(unittest.TestCase):
    def test_lost_failed_and_unrelated_jobs_cannot_complete(self):
        for result, path in (("done", "/job/7"), ("failed", "/job/7"), ("done", "/job/other"), (None, None)):
            with self.subTest(result=result, path=path):
                bus, manager, loop = Mock(), Mock(), Mock()
                callbacks = []
                def tick():
                    if result is None:
                        callbacks[0]()
                    else:
                        bus.add_signal_receiver.call_args.args[0](7, path, "fixture.service", result)
                loop.run.side_effect = tick
                def timer(_seconds, callback):
                    callbacks.append(callback)
                    return 1
                with patch("systemd_job.dbus.Interface", return_value=manager), patch(
                    "systemd_job.GLib.MainLoop", return_value=loop
                ), patch("systemd_job.GLib.timeout_add_seconds", side_effect=timer), patch("systemd_job.GLib.source_remove"):
                    if result == "done" and path == "/job/7":
                        self.assertEqual(owned_job(bus, "fixture.service", lambda _manager: "/job/7"), "/job/7")
                    else:
                        with self.assertRaisesRegex(RuntimeError, "unknown or failed"):
                            owned_job(bus, "fixture.service", lambda _manager: "/job/7")
                    bus.close.assert_called_once()
                    manager.Subscribe.assert_called_once_with(timeout=5)




class CustodyAndEntryTest(unittest.TestCase):
    setUp = NativeObserverTest.setUp
    write_process = NativeObserverTest.write_process

    def test_unknown_receipt_failure_retains_actual_descriptor(self):
        class Parked(BaseException):
            pass
        descriptors = []
        real_acquire = native.acquire_lock
        def acquire():
            descriptor, identity = real_acquire()
            descriptors.append(descriptor)
            return descriptor, identity
        with patch.object(native, "LOCK", self.root / "owned-lock"), patch.object(
            native, "frozen_inputs", return_value=self.source
        ), patch.object(native, "process_identity", return_value=self.owner), patch.object(
            native, "holder_budget", return_value=[{"owned": "fixture"}]
        ), patch.object(native.os, "getuid", return_value=1000), patch.object(
            native.os, "getgid", return_value=1000
        ), patch.object(native.signal, "signal"), patch.object(native, "acquire_lock", side_effect=acquire), patch.object(
            native, "append_receipt", side_effect=OSError("receipt disk failure")
        ), patch.object(native, "park_unknown", side_effect=Parked), patch.object(native.os, "close", wraps=native.os.close) as close:
            (self.proc / "self/cgroup").write_text("0::/outside")
            with self.assertRaises(Parked):
                native.hold_attempt(self.attempt)
            descriptor = descriptors[0]
            close.assert_not_called()
            self.assertFalse(native.os.get_inheritable(descriptor))
            self.assertGreater(native.os.fstat(descriptor).st_ino, 0)
            other = native.os.open(self.root / "owned-lock", native.os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    native.fcntl.flock(other, native.fcntl.LOCK_EX | native.fcntl.LOCK_NB)
            finally:
                native.os.close(other)
                native.os.close(descriptor)

    def test_actual_child_does_not_inherit_owned_descriptor(self):
        with patch.object(native, "LOCK", self.root / "owned-lock"):
            descriptor, _identity = native.acquire_lock()
            try:
                code = ('import os,sys,fcntl\n'
                        'try: os.fstat(int(sys.argv[1]))\n'
                        'except OSError: pass\n'
                        'else: raise SystemExit(9)\n'
                        'fd=os.open(sys.argv[2],os.O_RDWR)\n'
                        'try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n'
                        'except BlockingIOError: pass\n'
                        'else: raise SystemExit(10)\n'
                        'finally: os.close(fd)\n')
                child = native.subprocess.run(["/usr/bin/python3", "-I", "-S", "-B", "-c", code,
                                               str(descriptor), str(self.root / "owned-lock")],
                                              close_fds=True, timeout=5, check=False,
                                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                self.assertEqual(child.returncode, 0)
            finally:
                native.os.close(descriptor)

    def test_partial_start_is_unknown_and_parent_does_not_close_first(self):
        observation = native.Observation(self.owner, self.source, self.host, "fixture observer mount\n",
                                         [self.parent.unit, self.daemon.unit], [self.parent], [])
        with patch.object(native.Attempt, "stop") as stop:
            with self.assertRaisesRegex(RuntimeError, "start reply"):
                self.attempt.teardown(observation)
            stop.assert_not_called()

    def test_receipt_error_prevents_native_start(self):
        observation = native.Observation(self.owner, self.source, self.host, "fixture observer mount\n")
        with patch.object(native, "append_receipt", side_effect=OSError("disk full")), patch.object(native, "owned_job") as job:
            with self.assertRaises(OSError):
                self.attempt.start(self.parent.unit, observation)
            job.assert_not_called()
            self.assertEqual(observation.intents, [])

    def test_short_client_completion_joins_actual_witness(self):
        witness = {"boot": self.boot, "unit": self.info.unit, "invocation": self.info.invocation.hex(),
                   "cgroup": "/fixture.slice/" + self.info.unit, "pid": 201, "starttime": 202,
                   "ppid": 5, "pgrp": 201, "argv": native.client_argv("docker", self.attempt.p, self.attempt.r)}
        self.attempt.p.mkdir()
        (self.attempt.p / "docker-entry.json").write_text(json.dumps(witness))
        (self.attempt.p / "docker-plan.json").write_text(json.dumps({"cgroup": witness["cgroup"]}))
        raw = b'{"ID":"fixture"}\n'
        (self.attempt.p / "info.json").write_bytes(raw)
        (self.attempt.p / "info.stderr").write_bytes(b"owned fixture stderr\n")
        service = {"ExecMainPID": 201, "ExecMainCode": 1, "ExecMainStatus": 0, "Result": "success"}
        with patch.object(native, "properties", return_value=service), patch.object(native.Attempt, "identity", return_value=self.info):
            actor = self.attempt.completed_client(self.info)
            self.assertEqual((actor.pid, actor.starttime, actor.cgroup), (201, 202, witness["cgroup"]))
            evidence = self.attempt.client_output(self.info)
            self.assertEqual(evidence["unit"]["job"], self.info.job)
            self.assertEqual(evidence["witness"], witness)
            self.assertEqual(evidence["completion"], service)
            self.assertEqual(evidence["buffers"]["info.json"], {
                "size": len(raw), "sha256": native.hashlib.sha256(raw).hexdigest(), "raw": raw.hex()})
            for key, value in (("ExecMainPID", 999), ("ExecMainCode", 2), ("ExecMainStatus", 1), ("Result", "failed")):
                with self.subTest(key=key), patch.object(native, "properties", return_value={**service, key: value}), self.assertRaisesRegex(RuntimeError, "completion"):
                    self.attempt.completed_client(self.info)
                with patch.object(native, "properties", return_value={**service, key: value}):
                    failed = self.attempt.client_output(self.info)
                    self.assertIsNotNone(failed["join_error"])
                    self.assertEqual(failed["buffers"]["info.json"]["raw"], raw.hex())


class JobSetupFinalizerTest(unittest.TestCase):
    def test_setup_and_early_signal_finalizers(self):
        for failure in ("receiver", "subscribe", "timer", "early", "operation"):
            with self.subTest(failure=failure):
                bus, manager = Mock(), Mock()
                if failure == "receiver":
                    bus.add_signal_receiver.side_effect = RuntimeError("receiver")
                if failure == "subscribe":
                    manager.Subscribe.side_effect = RuntimeError("subscribe")
                def operation(_manager):
                    if failure == "operation":
                        raise RuntimeError("lost reply")
                    bus.add_signal_receiver.call_args.args[0](7, "/job/7", "fixture.service", "done")
                    return "/job/7"
                with patch("systemd_job.dbus.Interface", return_value=manager), patch("systemd_job.GLib.MainLoop"), patch(
                    "systemd_job.GLib.timeout_add_seconds", side_effect=RuntimeError("timer") if failure == "timer" else None,
                    return_value=9
                ), patch("systemd_job.GLib.source_remove") as remove:
                    if failure == "early":
                        self.assertEqual(owned_job(bus, "fixture.service", operation), "/job/7")
                    else:
                        with self.assertRaises(RuntimeError):
                            owned_job(bus, "fixture.service", operation)
                    bus.close.assert_called_once()
                    if failure != "receiver":
                        bus.add_signal_receiver.return_value.remove.assert_called_once()
                    if failure in ("early", "operation"):
                        remove.assert_called_once_with(9)


class NativeInputProfileTest(unittest.TestCase):
    def test_native_loading_refuses_unproved_changed_or_shadow_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "compiled-native-fixture"
            source.write_bytes(b"fixed native input")
            profile = root / "profile.json"
            value = {"application_enabled": False, "stdlib_search": list(entry.sys.path),
                     "operations": {"holder": True}, "import_inputs_reviewed": True,
                     "membership": {}, "required_absences": [str(root / "shadow")],
                     "files": native.digest_map((source,))}
            profile.write_text(json.dumps(value))
            profile.with_name("native-api-inputs.sha256").write_text(
                native.digest_map((source,))[str(source)] + "  " + str(source) + "\n")
            flags = Mock(isolated=True, no_site=True, dont_write_bytecode=True)
            with patch.object(entry, "PROFILE", profile), patch.object(entry.sys, "flags", flags), patch.object(entry.sys, "modules", {}):
                with self.assertRaisesRegex(RuntimeError, "source-unproved"):
                    entry.checked_profile()
                self.assertFalse(entry.checked_profile("import-only")["application_enabled"])
                value["application_enabled"] = True
                profile.write_text(json.dumps(value))
                self.assertEqual(entry.checked_profile()["files"], native.digest_map((source,)))
                source.write_bytes(b"changed")
                with self.assertRaisesRegex(RuntimeError, "input changed"):
                    entry.checked_profile()
                source.write_bytes(b"fixed native input")
                (root / "shadow").write_bytes(b"unreviewed")
                with self.assertRaisesRegex(RuntimeError, "absence"):
                    entry.checked_profile()

    def test_import_only_does_not_construct_attempt_or_call_operations(self):
        with patch.object(entry, "checked_profile", return_value={"application_enabled": False}), patch.object(
            entry, "load_owners") as load, patch.object(entry.sys, "stdout") as output:
            entry.import_only()
            load.assert_called_once_with({"application_enabled": False}, True)
            load.return_value.Attempt.assert_not_called()
            output.buffer.write.assert_called_once()


class OwnedHolderTest(unittest.TestCase):
    def exercise(self, case, status=None, exitcode=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").write_bytes(b"fixed fixture source")
            fixture = Path(__file__).resolve().with_name("native_holder_fixture.py")
            with (root / "stdout").open("wb") as stdout, (root / "stderr").open("wb") as stderr:
                holder = subprocess.Popen(["/usr/bin/python3", "-I", "-S", "-B", str(fixture),
                                           "holder", case, str(root)], close_fds=True,
                                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                                          stdout=stdout, stderr=stderr)
                try:
                    primary = root / "daemon-only-pending-00000000000000000000000000000001.json"
                    target = root / "holder-return.json" if status else primary.with_suffix(".holder-unknown.json")
                    if case == "receipt-error":
                        target = root / "receipt-error-ready"
                    deadline = time.monotonic() + 18
                    while not target.exists():
                        if holder.poll() is not None or time.monotonic() > deadline:
                            self.fail("holder fixture did not reach expected checkpoint " + (root / "stderr").read_text())
                        time.sleep(0.01)
                    lock = os.open(root / "canonical-lock", os.O_RDWR | os.O_CLOEXEC)
                    try:
                        if status:
                            self.assertEqual(holder.wait(timeout=5), 0)
                            self.assertEqual(json.loads(target.read_bytes()), {"status": status})
                            closed = json.loads(primary.with_suffix(".holder-closed.json").read_bytes())
                            self.assertEqual(closed["finite_exit"]["returncode"], exitcode)
                            self.assertEqual(closed["recheck_exit"]["returncode"], 0)
                            self.assertEqual(closed["status"], status)
                            native.fcntl.flock(lock, native.fcntl.LOCK_EX | native.fcntl.LOCK_NB)
                            self.assertEqual([os.fstat(lock).st_dev, os.fstat(lock).st_ino], closed["lock"])
                            native.fcntl.flock(lock, native.fcntl.LOCK_UN)
                        else:
                            self.assertIsNone(holder.poll())
                            with self.assertRaises(BlockingIOError):
                                native.fcntl.flock(lock, native.fcntl.LOCK_EX | native.fcntl.LOCK_NB)
                            holder.send_signal(signal.SIGTERM)
                            with self.assertRaises(subprocess.TimeoutExpired):
                                holder.wait(timeout=0.1)
                            with self.assertRaises(BlockingIOError):
                                native.fcntl.flock(lock, native.fcntl.LOCK_EX | native.fcntl.LOCK_NB)
                        if case != "receipt-error":
                            contention = json.loads((root / "finite-contention.json").read_bytes())
                            self.assertFalse(contention["inherited"])
                            pending = json.loads(primary.read_bytes())
                            self.assertEqual(contention["inode"], pending["lock"])
                            finite_exit = json.loads(primary.with_suffix(".finite-exit.json").read_bytes())
                            if case == "timeout":
                                self.assertTrue(finite_exit["timed_out"])
                                self.assertLess(finite_exit["returncode"], 0)
                            if case == "recheck-timeout":
                                recheck_exit = json.loads(primary.with_suffix(".recheck-exit.json").read_bytes())
                                self.assertTrue(recheck_exit["timed_out"])
                                self.assertLess(recheck_exit["returncode"], 0)
                    finally:
                        os.close(lock)
                finally:
                    if holder.poll() is None:
                        holder.kill()
                    holder.wait(timeout=5)

    def test_clean_closure_releases_actual_inode(self):
        self.exercise("clean", "qualified-and-closed", 0)

    def test_failed_qualification_releases_after_closure(self):
        self.exercise("failed", "failed-but-closed", 0)

    def test_nonzero_after_result_fails_qualification(self):
        self.exercise("nonzero", "failed-but-closed", 17)

    def test_signal_after_result_fails_qualification(self):
        self.exercise("signal", "failed-but-closed", -signal.SIGKILL)

    def test_missing_result_retains_actual_holder(self):
        self.exercise("missing")

    def test_malformed_result_retains_actual_holder(self):
        self.exercise("malformed")

    def test_oversized_result_retains_actual_holder(self):
        self.exercise("oversized")

    def test_source_drift_fails_but_closes(self):
        self.exercise("source-drift", "failed-but-closed", 0)

    def test_receipt_error_retains_actual_holder(self):
        self.exercise("receipt-error")

    def test_nonresponsive_finite_child_retains_holder(self):
        self.exercise("timeout")

    def test_nonresponsive_recheck_retains_holder_recovery(self):
        self.exercise("recheck-timeout")

    def test_nonzero_recheck_after_result_retains_holder(self):
        self.exercise("recheck-nonzero")

    def test_regular_read_and_result_writer_enforce_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized"
            with path.open("wb") as stream:
                stream.truncate(native.MAX_RESULT + 1)
            with self.assertRaisesRegex(RuntimeError, "bounded"):
                native.read_bounded(path, native.MAX_RESULT)
            destination = Path(directory) / "refused"
            with self.assertRaisesRegex(RuntimeError, "bound"):
                native.write_evidence(destination, b"x" * (native.MAX_RESULT + 1))
            self.assertFalse(destination.exists())

    def test_actual_producer_stops_at_file_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native-output"
            code = ('import os,resource,sys\n'
                    'resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536))\n'
                    'fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n'
                    'while True: os.write(fd,b"x"*4096)\n')
            result = subprocess.run(["/usr/bin/python3", "-I", "-S", "-B", "-c", code, str(output)],
                                    close_fds=True, timeout=5, check=False, capture_output=True,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.stat().st_size, 65536)


if __name__ == "__main__":
    unittest.main()
