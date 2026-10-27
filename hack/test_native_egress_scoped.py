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
from pathlib import Path
import unittest


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


if __name__ == "__main__":
    unittest.main()
