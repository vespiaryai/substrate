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

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE = Path(__file__).with_name("native-egress-scoped.py")
SPEC = importlib.util.spec_from_file_location("native_egress_scoped", MODULE)
egress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(egress)


class RenderTest(unittest.TestCase):
    def test_reviewed_images_replace_only_the_egress_markers(self):
        native = "registry/atenet@sha256:" + "a" * 64
        envoy = "registry/envoy@sha256:" + "b" * 64
        raw = egress.render(native, envoy).decode()
        self.assertEqual(raw.count("image: " + native), 2)
        self.assertEqual(raw.count("image: " + envoy), 1)
        self.assertNotIn("#ATE_EGRESS_INJECT_FLAGS", raw)
        self.assertIn("--mode=egress", raw)
        self.assertIn("name: sdsmint", raw)
        self.assertIn("name: envoy", raw)
        self.assertIn("name: ext-proc", raw)


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.native = "registry/atenet@sha256:" + "a" * 64
        self.envoy = "registry/envoy@sha256:" + "b" * 64
        rendered = egress.render(self.native, self.envoy)
        (self.path / "atenet-egress.yaml").write_bytes(rendered)
        self.before = dict.fromkeys(egress.OBJECTS)
        self.cluster = {"context": "reviewed-context"}
        self.record = {
            "state": "prepared_no_write",
            "namespace": "ate-system",
            "atenet_image": self.native,
            "envoy_image": self.envoy,
            "source_sha256": egress.digest(egress.SOURCE.read_bytes()),
            "manifest_sha256": egress.digest(rendered),
            "policy_sha256": egress.digest(egress.POLICY.read_bytes()),
            "binding": self.cluster,
            "before": self.before,
        }
        self.receipt = self.path / "operation.json"
        self.write_record()

    def write_record(self):
        self.receipt.write_text(json.dumps(self.record))

    def apply(self, snapshots, run):
        argv = ["native-egress-scoped.py", "apply", "--namespace=ate-system",
                "--atenet-image=" + self.native, "--envoy-image=" + self.envoy,
                "--receipt-dir=" + str(self.path)]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(egress, "binding", return_value=self.cluster), \
             mock.patch.object(egress, "snapshot", side_effect=snapshots), \
             mock.patch.object(egress.subprocess, "run", side_effect=run):
            egress.main()

    def test_preexisting_target_refused_before_write(self):
        existing = dict(self.before)
        existing["service/atenet-egress"] = {"uid": "other", "resourceVersion": "1"}
        run = mock.Mock()
        with self.assertRaisesRegex(RuntimeError, "resource UID or version changed"):
            self.apply([existing], run)
        run.assert_not_called()
        self.assertEqual(json.loads(self.receipt.read_text())["state"], "prepared_no_write")

    def test_prepared_existing_target_refused(self):
        self.before["service/atenet-egress"] = {"uid": "other", "resourceVersion": "1"}
        self.write_record()
        run = mock.Mock()
        with self.assertRaisesRegex(RuntimeError, "existed at preparation"):
            self.apply([], run)
        run.assert_not_called()

    def test_create_commands_and_bound_context(self):
        after_ca = dict(self.before)
        after_ca["secret/egress-mitm-ca-pool"] = {"uid": "ca", "resourceVersion": "1"}
        after = {name: {"uid": name, "resourceVersion": "1"} for name in egress.OBJECTS}
        def run(*args, **kwargs):
            saved = json.loads(self.receipt.read_text())
            self.assertEqual(saved["state"], "attempted_write")
            self.assertEqual(saved["attempts"][-1], args[0])
            return subprocess.CompletedProcess([], 0)
        run = mock.Mock(side_effect=run)
        self.apply([self.before, after_ca, after], run)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ["mise", "exec", "--", "go", "run", "./cmd/ate-setup", "--no-dev-env",
             "--namespace=ate-system", "--context=reviewed-context", "create", "egress-mitm-ca-pool"],
            ["kubectl", "--context=reviewed-context", "-n", "ate-system", "create", "-f", str(self.path / "atenet-egress.yaml")],
            ["kubectl", "--context=reviewed-context", "-n", "ate-system", "create", "-f", str(egress.POLICY)],
        ])
        self.assertEqual(json.loads(self.receipt.read_text())["state"], "applied_readback")
        self.assertEqual(len(json.loads(self.receipt.read_text())["attempts"]), 3)

    def test_metadata_uses_prepared_context(self):
        response = subprocess.CompletedProcess([], 0, '{"metadata":{"uid":"u","resourceVersion":"1"}}', "")
        with mock.patch.object(egress.subprocess, "run", return_value=response) as run:
            self.assertEqual(egress.metadata("ate-system", "service/atenet-egress", "reviewed-context"),
                             {"uid": "u", "resourceVersion": "1"})
        self.assertEqual(run.call_args.args[0],
                         ["kubectl", "--context=reviewed-context", "-n", "ate-system", "get",
                          "service/atenet-egress", "-o", "json"])

    def test_timeout_after_attempt_is_uncertain_and_blocks_replay(self):
        def timeout(*args, **kwargs):
            self.assertEqual(json.loads(self.receipt.read_text())["state"], "attempted_write")
            raise subprocess.TimeoutExpired("mise", 1)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.apply([self.before], timeout)
        self.assertEqual(json.loads(self.receipt.read_text())["state"], "uncertain_write")
        with self.assertRaisesRegex(RuntimeError, "attempted write"):
            self.apply([], mock.Mock())

    def test_interrupt_after_attempt_is_uncertain(self):
        def interrupt(*args, **kwargs):
            self.assertEqual(json.loads(self.receipt.read_text())["state"], "attempted_write")
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.apply([self.before], interrupt)
        self.assertEqual(json.loads(self.receipt.read_text())["state"], "uncertain_write")

    def test_existing_ca_secret_is_preserved(self):
        self.before["secret/egress-mitm-ca-pool"] = {"uid": "existing-ca", "resourceVersion": "3"}
        self.write_record()
        after = {name: {"uid": name, "resourceVersion": "1"} for name in egress.OBJECTS}
        after["secret/egress-mitm-ca-pool"] = self.before["secret/egress-mitm-ca-pool"]
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        self.apply([self.before, self.before, after], run)
        saved = json.loads(self.receipt.read_text())
        self.assertEqual(saved["after"]["secret/egress-mitm-ca-pool"], self.before["secret/egress-mitm-ca-pool"])

    def test_snapshot_failure_after_success_is_uncertain(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        with self.assertRaisesRegex(RuntimeError, "readback failed"):
            self.apply([self.before, RuntimeError("readback failed")], run)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(json.loads(self.receipt.read_text())["state"], "uncertain_write")

    def test_already_exists_stops_without_policy_create(self):
        after_ca = dict(self.before)
        after_ca["secret/egress-mitm-ca-pool"] = {"uid": "ca", "resourceVersion": "1"}
        run = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 1)])
        with self.assertRaisesRegex(RuntimeError, "outcome uncertain"):
            self.apply([self.before, after_ca], run)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(json.loads(self.receipt.read_text())["state"], "uncertain_write")


if __name__ == "__main__":
    unittest.main()
