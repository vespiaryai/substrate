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
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, PropertyMock, patch

import dbus

import native_api_observer as native
from systemd_job import owned_job


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
        self.parent = native.NativeIdentity(self.boot, self.attempt.units[0], b"p" * 16,
                                            "/fixture.slice", "/job/1")
        self.daemon = native.NativeIdentity(self.boot, self.attempt.units[1], b"d" * 16,
                                            "/fixture.slice/daemon.service", "/job/2",
                                            101, 1001, 5, 101)
        self.owner = native.NativeIdentity(self.boot, "outside-keeper", b"", "/outside", "",
                                           77, 777, 5, 77, ("python3",))
        self.api = native.NativeIdentity(self.boot, self.attempt.units[3], b"a" * 16, "", "/job/4")
        self.info = dataclasses.replace(self.api, unit=self.attempt.units[2], invocation=b"i" * 16,
                                        job="/job/3")
        argv = ("rootlesskit", f"--state-dir={self.attempt.r}/rootlesskit", "--net=pasta",
                "--mtu=65520", "--slirp4netns-sandbox=auto", "--slirp4netns-seccomp=auto",
                "--disable-host-loopback", "--port-driver=implicit", "--copy-up=/etc",
                "--copy-up=/run", "--propagation=rslave", "--detach-netns",
                "/usr/bin/dockerd-rootless.sh", f"--config-file={self.attempt.p}/daemon.json", "--group=0")
        self.parent_actor = dataclasses.replace(self.daemon, argv=argv)
        self.child = dataclasses.replace(self.daemon, pid=102, starttime=1002, ppid=101, argv=("exe",))
        self.docker = dataclasses.replace(self.daemon, pid=103, starttime=1003, ppid=102,
                                          argv=("dockerd", f"--config-file={self.attempt.p}/daemon.json", "--group=0"))
        self.containerd = dataclasses.replace(self.daemon, pid=104, starttime=1004, ppid=103,
                                              pgrp=104, argv=("/usr/bin/containerd", "--config",
                                                            str(self.attempt.r / "exec/containerd/containerd.toml")))
        self.pasta = dataclasses.replace(self.daemon, pid=105, starttime=1005, ppid=5,
                                         pgrp=105, argv=("/usr/bin/pasta.avx2",))
        self.actors = (self.parent_actor, self.child, self.docker, self.containerd, self.pasta)
        for actor in (*self.actors, self.owner):
            self.write_process(actor)
        self.host = {"selected-host-fixture": "unchanged"}
        self.enterContext(patch.object(native, "host_state", return_value=self.host))
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

        def start(_attempt, unit):
            self.mutations.append(("start", unit))
            if unit == self.parent.unit:
                return self.parent
            if unit == self.daemon.unit:
                self.metadata()
                return self.daemon
            if unit == self.info.unit:
                (self.attempt.p / "info.json").write_text(json.dumps(self.docker_value()))
                return self.info
            if unit == self.api.unit:
                if fault == "timeout":
                    raise TimeoutError("native five-second request timeout")
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
            if fault:
                with self.assertRaises((RuntimeError, ValueError, TimeoutError, PermissionError)):
                    self.attempt.observe(self.owner, self.source, native.time.monotonic() + 300)
                self.assertFalse(any(suffix == ".closed" for suffix, _ in self.receipts))
                if fault in ("denial", "invocation"):
                    self.assertNotIn(("start", self.api.unit), self.mutations)
                if fault not in ("populated", "stale-socket", "lost-job", "failed-job", "unrelated-job"):
                    self.assertFalse(any(kind == "stop" for kind, _ in self.mutations))
                elif fault in ("lost-job", "failed-job", "unrelated-job"):
                    self.assertEqual([kind for kind, _ in self.mutations].count("stop"), 1)
                else:
                    self.assertNotIn(("stop", self.parent.unit), self.mutations)
            else:
                self.attempt.observe(self.owner, self.source, native.time.monotonic() + 300)
                self.assertEqual(self.mutations, [("start", item) for item in self.attempt.units] +
                                 [("stop", item) for item in (self.api.unit, self.info.unit,
                                                              self.daemon.unit, self.parent.unit)])
                self.assertEqual(self.receipts[-1][0], ".closed")
                closure = self.receipts[-1][1]["native_service_closure"]
                self.assertEqual(closure["outside_holders"], "unmeasured")
                self.assertEqual(closure["detached_namespace_identity"], "unmeasured")
                self.assertNotIn("owned_reference_closure", self.receipts[-1][1])
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
        original = Path.read_bytes
        def denied(path):
            if path == self.proc / str(self.child.pid) / "cmdline":
                raise PermissionError("required ordinary metadata")
            return original(path)
        with patch.object(Path, "read_bytes", denied), self.assertRaises(PermissionError):
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


if __name__ == "__main__":
    unittest.main()
