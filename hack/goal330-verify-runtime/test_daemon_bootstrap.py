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

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import daemon_bootstrap as bootstrap


class DaemonOnlyTest(unittest.TestCase):
    def test_installed_native_unit_contracts(self):
        root = Path("/usr/share/dbus-1/interfaces")
        for kind, required in {
            "Unit": {"InvocationID": "ay", "Transient": "b", "StopWhenUnneeded": "b"},
            "Service": {"RuntimeMaxUSec": "t", "TimeoutStopUSec": "t", "ControlGroup": "s"},
            "Slice": {"CPUQuotaPerSecUSec": "t", "MemoryMax": "t", "MemorySwapMax": "t", "TasksMax": "t"},
        }.items():
            with self.subTest(kind=kind):
                tree = ET.parse(root / f"org.freedesktop.systemd1.{kind}.xml")
                actual = {node.attrib["name"]: node.attrib["type"] for node in tree.iter("property")}
                self.assertEqual({name: actual[name] for name in required}, required)

    def info(self):
        return {
            "ID": "owned-daemon", "ServerVersion": "29.9.0", "Containers": 0, "Images": 0,
            "DockerRootDir": str(bootstrap.P / "data"), "CgroupDriver": "systemd",
            "CgroupVersion": "2", "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]],
            "SecurityOptions": ["name=rootless", "name=seccomp,profile=builtin", "name=cgroupns"],
        }

    def test_zero_object_native_info(self):
        self.assertEqual(bootstrap.check_info(self.info()), "owned-daemon")
        for change in ({"Images": 1}, {"Containers": 1}, {"DockerRootDir": "/var/lib/docker"},
                       {"DriverStatus": []}, {"SecurityOptions": []}, {"CgroupDriver": "cgroupfs"}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                bootstrap.check_info(self.info() | change)

    def test_native_managed_containerd(self):
        config = (f'root = "{bootstrap.P}/data/containerd/daemon"\n'
                  f'state = "{bootstrap.R}/exec/containerd/daemon"\n'
                  f'[grpc]\naddress = "{bootstrap.R}/exec/containerd/containerd.sock"\n'
                  f'[debug]\naddress = "{bootstrap.R}/exec/containerd/containerd-debug.sock"\n').encode()
        argv = ("/usr/bin/containerd", "--config", f"{bootstrap.R}/exec/containerd/containerd.toml")
        self.assertEqual(bootstrap.managed_containerd(config, argv)["state"],
                         f"{bootstrap.R}/exec/containerd/daemon")
        with self.assertRaises(RuntimeError):
            bootstrap.managed_containerd(config.replace(str(bootstrap.P).encode(), b"/var/lib"), argv)
        with self.assertRaises(RuntimeError):
            bootstrap.managed_containerd(config, ("/usr/bin/containerd",))

    def test_slice_retains_actual_bounds(self):
        props = dict(bootstrap.slice_properties())
        self.assertFalse(props["StopWhenUnneeded"])
        self.assertEqual(int(props["CPUQuotaPerSecUSec"]), 2000000)
        self.assertEqual(int(props["MemoryMax"]), 4294967296)
        self.assertEqual(int(props["MemorySwapMax"]), 0)
        self.assertEqual(int(props["TasksMax"]), 512)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group = root / "owned.slice"
            group.mkdir()
            values = {"cpu.max": "200000 100000", "memory.max": "4294967296",
                      "memory.swap.max": "0", "pids.max": "512",
                      "cgroup.controllers": "cpu memory pids", "cgroup.subtree_control": ""}
            for name, value in values.items():
                (group / name).write_text(value)
            with patch.object(bootstrap, "CGROUP", root):
                self.assertEqual(bootstrap.bounded_parent("/owned.slice")[0]["memory.swap.max"], "0")
                for name, value in {"cpu.max": "max 100000", "memory.max": "max",
                                    "memory.swap.max": "1", "pids.max": "513"}.items():
                    with self.subTest(name=name):
                        (group / name).write_text(value)
                        with self.assertRaises(RuntimeError):
                            bootstrap.bounded_parent("/owned.slice")
                        (group / name).write_text(values[name])

    def test_daemon_has_finite_native_lifetime(self):
        props = dict(bootstrap.daemon_properties())
        self.assertEqual(int(props["RuntimeMaxUSec"]), 180000000)
        self.assertEqual(int(props["TimeoutStopUSec"]), 15000000)
        self.assertEqual(str(props["Slice"]), bootstrap.SLICE)
        self.assertEqual(str(props["KillMode"]), "control-group")
        self.assertEqual(str(props["Restart"]), "no")
        argv = bootstrap.daemon_argv()
        self.assertIn(f"XDG_RUNTIME_DIR={bootstrap.R}/xdg", argv)
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", argv)
        self.assertEqual(argv[-3:], ["/usr/bin/dockerd-rootless.sh",
                                   f"--config-file={bootstrap.P}/daemon.json", "--group=0"])
        config = bootstrap.daemon_config()
        self.assertEqual(config["hosts"], [bootstrap.URI])
        self.assertNotIn("selinux-enabled", config)
        self.assertNotIn("storage-driver", config)

    def test_pending_receipt_refuses_reuse_without_changing_evidence(self):
        owner = bootstrap.ProcessIdentity(71, 91, 1, "/owner", ("keeper",), ())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pending.json"
            bootstrap.pending_receipt(path, {"source": "hash"}, owner, "boot")
            original = path.read_bytes()
            self.assertEqual(json.loads(original)["status"], "pending")
            with self.assertRaises(FileExistsError):
                bootstrap.pending_receipt(path, {"source": "changed"}, owner, "other-boot")
            self.assertEqual(path.read_bytes(), original)

    def test_stop_refuses_replaced_invocation_before_mutation(self):
        old = bootstrap.UnitIdentity(bootstrap.DAEMON, b"a" * 16, "/owned", "/job/1")
        new = bootstrap.UnitIdentity(bootstrap.DAEMON, b"b" * 16, "/owned", "/job/2")
        with patch.object(bootstrap, "user_bus", return_value=Mock()), patch.object(
                bootstrap, "identity", return_value=old) as current, patch.object(
                bootstrap, "owned_job", return_value="/job/3") as mutate:
            self.assertEqual(bootstrap.stop_owned(old), "/job/3")
            mutate.reset_mock()
            current.return_value = new
            with self.assertRaises(RuntimeError):
                bootstrap.stop_owned(old)
            mutate.assert_not_called()

    def test_actual_cgroup_must_be_empty_after_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group = root / "owned.slice"
            group.mkdir()
            (group / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            parent = bootstrap.UnitIdentity(bootstrap.SLICE, b"a" * 16, "/owned.slice", "/job/1")
            with patch.object(bootstrap, "CGROUP", root):
                with self.assertRaisesRegex(RuntimeError, "populated"):
                    bootstrap.check_stopped_objects(parent, [])

    def test_denial_is_not_absence(self):
        path = Mock()
        path.lstat.side_effect = PermissionError("denied")
        with self.assertRaises(PermissionError):
            bootstrap.present(path)

    def test_entrypoint_refuses_before_runtime_mutation(self):
        for error in (FileExistsError("pending"), PermissionError("denied")):
            with (
                self.subTest(error=error),
                patch.object(bootstrap.os, "umask"),
                patch.object(bootstrap.signal, "signal"),
                patch.object(bootstrap.signal, "alarm") as alarm,
                patch.object(bootstrap.os, "open", return_value=71),
                patch.object(bootstrap.fcntl, "flock"),
                patch.object(bootstrap.os, "readlink", return_value="ns:[1]"),
                patch.object(bootstrap.Path, "read_text", return_value="boot"),
                patch.object(bootstrap.Path, "read_bytes", return_value=b"source"),
                patch.object(bootstrap, "process_identity", return_value=Mock()),
                patch.object(bootstrap, "pending_receipt", side_effect=error),
                patch.object(bootstrap, "start_owned") as mutate,
                patch.object(bootstrap, "create_private_files") as create,
            ):
                with self.assertRaises(type(error)):
                    bootstrap.daemon_only()
                alarm.assert_called_once_with(300)
                mutate.assert_not_called()
                create.assert_not_called()


class OwnedScopeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.proc = self.root / "proc"
        self.group = self.root / "cgroup"
        self.runtime = self.root / "runtime"
        for name, value in {"PROC": self.proc, "CGROUP": self.group,
                            "P": self.root / "persistent", "R": self.runtime}.items():
            patcher = patch.object(bootstrap, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        (self.group / "owned.slice").mkdir(parents=True)
        self.events = self.group / "owned.slice/cgroup.events"
        self.events.write_text("populated 0\nfrozen 0\n")
        (self.proc / "self/fd").mkdir(parents=True)
        self.mounts = "1 0 0:1 / / rw - tmpfs tmpfs rw\n"
        (self.proc / "self/mountinfo").write_text(self.mounts)
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        (self.proc / "sys/kernel/random/boot_id").write_text("owned-boot\n")
        self.parent = bootstrap.UnitIdentity(bootstrap.SLICE, b"a" * 16, "/owned.slice", "/job/1")
        self.write_process(71, 91, "/observer")
        self.owner = bootstrap.process_identity(71, "/observer")
        self.write_process(72, 92, "/owned.slice/daemon.service")
        self.actor = bootstrap.process_identity(72, "/owned.slice")
        (self.runtime / "rootlesskit").mkdir(parents=True)
        (self.runtime / "rootlesskit/child_pid").write_text("72\n")
        self.netns = self.proc / "72/root" / (self.runtime / "rootlesskit/netns").relative_to("/")
        self.netns.parent.mkdir(parents=True)
        self.netns.touch()
        metadata = self.netns.stat()
        self.net_mount = (f"2 1 {os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)} "
                          f"net:[{metadata.st_ino}] {self.runtime}/rootlesskit/netns rw - nsfs nsfs rw\n")
        (self.proc / "72/mountinfo").write_text(self.net_mount)
        self.detached = bootstrap.detached_netns(self.parent, [self.actor])
        (self.proc / "72/stat").unlink()

    def write_process(self, pid, starttime, cgroup):
        root = self.proc / str(pid)
        (root / "ns").mkdir(parents=True, exist_ok=True)
        (root / "stat").write_text(f"{pid} (owned) " + " ".join(["S", "1", *["0"] * 17, str(starttime)]))
        (root / "cgroup").write_text(f"0::{cgroup}\n")
        (root / "cmdline").write_bytes(b"/usr/bin/dockerd\0")
        for name in ("mnt", "net", "user"):
            path = root / "ns" / name
            if not path.is_symlink():
                path.symlink_to(f"{name}:[{pid}]")

    def close(self):
        return bootstrap.owned_references_closed(self.parent, [self.actor], self.detached,
                                                 self.owner, self.mounts, "owned-boot")

    def test_unreadable_unrelated_subject_is_never_queried(self):
        read_text = Path.read_text
        iterdir = Path.iterdir
        queries = []

        def scoped_read(path, *args, **kwargs):
            queries.append(path)
            if path == self.proc / "3089" or self.proc / "3089" in path.parents:
                raise PermissionError("unrelated subject denied")
            return read_text(path, *args, **kwargs)

        def scoped_list(path):
            if path in (self.proc, Path("/proc")):
                raise AssertionError("universal process census is forbidden")
            return iterdir(path)

        with patch.object(Path, "read_text", scoped_read), patch.object(Path, "iterdir", scoped_list):
            closure = self.close()
            self.assertEqual(closure["contract"], "owned-actors-and-references")
            self.assertEqual(closure["outside_holders"], "unmeasured")
            self.assertTrue(queries)
            self.assertFalse(any(self.proc / "3089" in path.parents for path in queries))
            with self.assertRaises(PermissionError):
                (self.proc / "3089/stat").read_text()

    def test_owned_denial_is_not_absence(self):
        self.assertEqual(self.close()["contract"], "owned-actors-and-references")
        original = Path.read_text

        def denied(path, *args, **kwargs):
            if path == self.proc / "72/stat":
                raise PermissionError("owned metadata denied")
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", denied), self.assertRaises(PermissionError):
            self.close()

    def test_live_original_actor_refused_but_pid_reuse_is_not_original(self):
        self.write_process(72, 93, "/unrelated-reused-pid")
        self.assertEqual(self.close()["contract"], "owned-actors-and-references")
        self.write_process(72, 92, "/owned.slice/daemon.service")
        with self.assertRaisesRegex(RuntimeError, "remains alive"):
            self.close()

    def test_populated_unseen_descendant_refused(self):
        self.assertEqual(self.close()["contract"], "owned-actors-and-references")
        self.events.write_text("populated 1\nfrozen 0\n")
        with self.assertRaisesRegex(RuntimeError, "populated"):
            self.close()

    def test_escaped_owned_actor_refused(self):
        self.write_process(72, 92, "/owned.slice/daemon.service")
        self.assertEqual(bootstrap.process_identity(72, "/owned.slice").starttime, 92)
        (self.proc / "72/cgroup").write_text("0::/outside\n")
        with self.assertRaisesRegex(RuntimeError, "escaped"):
            bootstrap.process_identity(72, "/owned.slice")

    def test_stale_owned_socket_refused(self):
        self.assertEqual(self.close()["contract"], "owned-actors-and-references")
        (self.runtime / "docker.sock").touch()
        with self.assertRaisesRegex(RuntimeError, "retained socket"):
            self.close()

    def test_exported_observer_mount_refused(self):
        self.assertEqual(self.close()["contract"], "owned-actors-and-references")
        exported = self.net_mount.replace(f"{self.runtime}/rootlesskit/netns", "/exported-netns")
        (self.proc / "self/mountinfo").write_text(self.mounts + exported)
        with self.assertRaisesRegex(RuntimeError, "observer mount table"):
            self.close()

    def test_detached_netns_stat_must_match_owned_nsfs_mount(self):
        self.write_process(72, 92, "/owned.slice/daemon.service")
        self.assertEqual(bootstrap.detached_netns(self.parent, [self.actor]).inode, self.netns.stat().st_ino)
        (self.proc / "72/mountinfo").write_text(self.net_mount.replace("net:[", "user:["))
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            bootstrap.detached_netns(self.parent, [self.actor])

    def test_observer_private_namespace_descriptor_refused(self):
        self.assertEqual(self.close()["observer_private_namespace_fds"], "none")
        (self.proc / "self/fd/7").symlink_to(f"net:[{self.detached.inode}]")
        with self.assertRaisesRegex(RuntimeError, "namespace descriptor"):
            self.close()

    def test_changed_boot_refused(self):
        self.assertEqual(self.close()["contract"], "owned-actors-and-references")
        (self.proc / "sys/kernel/random/boot_id").write_text("other-boot\n")
        with self.assertRaisesRegex(RuntimeError, "boot changed"):
            self.close()

    def test_native_terminal_state_and_job_required(self):
        unit = {"ActiveState": "inactive", "SubState": "dead", "Job": (0, "/"),
                "InvocationID": b"a" * 16}
        manager = Mock()
        manager.ListJobs.return_value = []
        with patch.object(bootstrap, "user_bus", return_value=Mock()), patch.object(
                bootstrap.dbus, "Interface", return_value=manager), patch.object(
                bootstrap, "properties", return_value=unit):
            self.assertEqual(bootstrap.stopped_unit(self.parent)["state"], "inactive/dead")
            for invocation in (b"", bytes(16)):
                with self.subTest(invocation=invocation), patch.object(
                        bootstrap, "properties", return_value=unit | {"InvocationID": invocation}):
                    self.assertEqual(bootstrap.stopped_unit(self.parent)["state"], "inactive/dead")
            for change in ({"ActiveState": "active"}, {"InvocationID": b"b" * 16}, {"Job": (1, "/job/1")}):
                with self.subTest(change=change), patch.object(
                        bootstrap, "properties", return_value=unit | change), self.assertRaises(RuntimeError):
                    bootstrap.stopped_unit(self.parent)
            manager.ListJobs.return_value = [(1, bootstrap.SLICE)]
            with self.assertRaisesRegex(RuntimeError, "still has a job"):
                bootstrap.stopped_unit(self.parent)

    def test_terminal_service_main_pid_and_native_absence(self):
        owned = bootstrap.UnitIdentity(bootstrap.DAEMON, b"a" * 16, "/owned.slice/daemon", "/job/1")
        unit = {"ActiveState": "inactive", "SubState": "dead", "Job": (0, "/"),
                "InvocationID": b"a" * 16, "MainPID": 0}
        manager = Mock()
        manager.ListJobs.return_value = []
        with patch.object(bootstrap, "user_bus", return_value=Mock()), patch.object(
                bootstrap.dbus, "Interface", return_value=manager), patch.object(
                bootstrap, "properties", return_value=unit) as properties:
            self.assertEqual(bootstrap.stopped_unit(owned)["state"], "inactive/dead")
            properties.return_value = unit | {"MainPID": 72}
            with self.assertRaisesRegex(RuntimeError, "main PID"):
                bootstrap.stopped_unit(owned)
            properties.side_effect = bootstrap.dbus.DBusException(
                "absent", name="org.freedesktop.systemd1.NoSuchUnit")
            self.assertEqual(bootstrap.stopped_unit(owned)["state"], "absent")
            properties.side_effect = bootstrap.dbus.DBusException(
                "denied", name="org.freedesktop.DBus.Error.AccessDenied")
            with self.assertRaises(bootstrap.dbus.DBusException):
                bootstrap.stopped_unit(owned)


if __name__ == "__main__":
    unittest.main()
