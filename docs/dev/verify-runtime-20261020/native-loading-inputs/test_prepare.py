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
import struct
import unittest

spec = importlib.util.spec_from_file_location('native_loading_prepare', Path(__file__).with_name('prepare.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class DataParserTest(unittest.TestCase):
    def test_static_elf_has_no_dependencies(self):
        body = bytearray(64)
        body[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', body, 18, 62)
        struct.pack_into('<HH', body, 54, 56, 0)
        self.assertEqual(prepare.dynamic(body), {
            'needed': [], 'rpath': [], 'runpath': [], 'interpreter': None})

    def test_foreign_architecture_refuses(self):
        body = bytearray(64)
        body[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', body, 18, 183)
        with self.assertRaisesRegex(RuntimeError, 'x86-64'):
            prepare.dynamic(body)

    def test_segment_outside_buffer_refuses(self):
        body = bytearray(120)
        body[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', body, 18, 62)
        struct.pack_into('<Q', body, 32, 64)
        struct.pack_into('<HH', body, 54, 56, 1)
        struct.pack_into('<IIQQQQQQ', body, 64, 1, 0, 120, 0, 0, 1, 1, 1)
        with self.assertRaisesRegex(RuntimeError, 'segment extent'):
            prepare.dynamic(body)


if __name__ == '__main__':
    unittest.main()
