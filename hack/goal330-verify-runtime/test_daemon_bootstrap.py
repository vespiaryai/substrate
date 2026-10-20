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
                bootstrap, "identity", return_value=new), patch.object(bootstrap, "owned_job") as mutate:
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


if __name__ == "__main__":
    unittest.main()
