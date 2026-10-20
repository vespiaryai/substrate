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

import sys
import _imp
import json


for api in ('_frozen_module_names', 'is_frozen', 'extension_suffixes'):
    if not callable(getattr(_imp, api, None)):
        raise RuntimeError('unsupported frozen/suffix API')

record = {'schema': 'interpreter-observation-1', 'executable': sys.executable,
          'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'version': sys.version,
          'search': list(sys.path), 'builtins': list(sys.builtin_module_names),
          'frozen_candidates': _imp._frozen_module_names(),
          'extension_suffixes': _imp.extension_suffixes()}
for field in ('search', 'builtins', 'frozen_candidates', 'extension_suffixes'):
    if type(record[field]) is not list or len(record[field]) > 4096:
        raise RuntimeError('unsupported inventory size/type')
record['frozen_active_flags'] = [_imp.is_frozen(name) for name in record['frozen_candidates']]
if any(type(flag) is not bool for flag in record['frozen_active_flags']):
    raise RuntimeError('unsupported frozen predicate')
record['frozen'] = [name for name, active in zip(record['frozen_candidates'],
                                               record['frozen_active_flags']) if active]
for field, value in record.items():
    if field == 'frozen_active_flags':
        continue
    values = value if type(value) is list else [value]
    for item in values:
        cap = 65536 if field == 'version' else 4096
        if type(item) is not str or not item or '\x00' in item or len(item.encode('utf-8')) > cap:
            raise RuntimeError('unsupported scalar')
body = bytearray()
encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(',', ':'))
for chunk in encoder.iterencode(record):
    encoded = chunk.encode('ascii')
    if len(body) + len(encoded) + 1 > 2097152:
        raise RuntimeError('observer output cap')
    body.extend(encoded)
body.extend(b'\n')
sys.stdout.buffer.write(body)
sys.stdout.buffer.flush()
