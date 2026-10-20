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

import unittest
from unittest.mock import Mock, patch

from systemd_job import owned_job


class OwnedJobTest(unittest.TestCase):
    def exercise(self, result, path="/job/7"):
        bus = Mock()
        manager = Mock()
        loop = Mock()
        operation = Mock(return_value="/job/7")

        def signal():
            callback = bus.add_signal_receiver.call_args.args[0]
            callback(7, path, "owned.slice", result)

        loop.run.side_effect = signal
        with patch("systemd_job.dbus.Interface", return_value=manager), patch(
            "systemd_job.GLib.MainLoop", return_value=loop
        ), patch("systemd_job.GLib.timeout_add_seconds", return_value=1), patch(
            "systemd_job.GLib.source_remove"
        ):
            try:
                return owned_job(bus, "owned.slice", operation)
            finally:
                self.assertEqual(
                    bus.add_signal_receiver.call_args.kwargs["arg2"], "owned.slice"
                )
                operation.assert_called_once_with(manager)
                manager.Subscribe.assert_called_once_with(timeout=5)
                bus.close.assert_called_once()

    def test_requires_exact_successful_job(self):
        self.assertEqual(self.exercise("done"), "/job/7")

    def test_rejects_failed_job(self):
        with self.assertRaisesRegex(RuntimeError, "failed owned job"):
            self.exercise("failed")

    def test_other_job_cannot_complete_owned_job(self):
        with self.assertRaisesRegex(RuntimeError, "failed owned job"):
            self.exercise("done", "/job/99")


if __name__ == "__main__":
    unittest.main()
