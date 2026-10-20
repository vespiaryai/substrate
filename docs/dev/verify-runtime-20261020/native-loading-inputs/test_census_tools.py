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

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import shlex
import signal
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name('census_tools.py')
FIXTURE = Path('/home/zack/.codex/orchestrate/vespiary-goal330/reviews/native-maintained-census-implementation/fixture-first')
spec = importlib.util.spec_from_file_location('census_tools_fixture', SOURCE)
census_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(census_tools)


class ArchiveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURE.mkdir(mode=0o700)

    def setUp(self):
        self.base = FIXTURE / self._testMethodName
        self.base.mkdir(mode=0o700)
        self.inputs = self.base / 'inputs'
        self.inputs.mkdir(mode=0o700)
        self.outputs = self.base / 'outputs'
        self.outputs.mkdir(mode=0o700)
        self.output = self.outputs / 'capture'

    def owner(self, **limits):
        return census_tools.Census(self.output, **limits)

    def test_same_buffer_and_candidate_corpus_separation(self):
        actor = self.inputs / 'actor'
        corpus = self.inputs / 'foreign-elf-fixture'
        actor.write_bytes(b'actor-buffer')
        corpus.write_bytes(b'\x7fELFforeign-corpus-only')
        owner = self.owner()
        row = owner.capture(str(actor), 'explicit-actor', eligible=True)
        other = owner.capture(str(corpus), 'stdlib-corpus')
        self.assertEqual(row['raw']['sha256'], hashlib.sha256(b'actor-buffer').hexdigest())
        self.assertEqual((self.output / row['raw']['name']).read_bytes(), b'actor-buffer')
        self.assertTrue(row['eligible'])
        self.assertFalse(other['eligible'])
        self.assertEqual(owner.capture(str(actor), 'manifest')['raw'], row['raw'])
        self.assertEqual(row['reasons'], ['explicit-actor', 'manifest'])
        owner.failure(census_tools.Incomplete('fixture-only'))
        result = json.loads((self.output / 'failure.json').read_bytes())
        self.assertFalse(any(result['authorities'].values()))
        self.assertEqual(result['selection'], 'unobserved')
        self.assertFalse((self.output / 'result.json').exists())

    def test_regular_directory_link_and_absence(self):
        target = self.inputs / 'target'
        target.write_bytes(b'body')
        link = self.inputs / 'alias'
        link.symlink_to('target')
        owner = self.owner()
        self.assertEqual(owner.capture(str(link), 'alias')['kind'], 'symlink')
        self.assertEqual(owner.regular_row(str(link))['raw']['size'], 4)
        missing = self.inputs / 'missing'
        self.assertEqual(owner.capture(str(missing), 'required-absence')['errno'], 2)
        self.assertEqual(owner.paths[str(self.inputs)]['names'], ['alias', 'target'])
        for path in tuple(owner.paths):
            owner.reobserve(path)

    def test_path_replacement_preserves_partial_raw(self):
        path = self.inputs / 'subject'
        path.write_bytes(b'A' * 32)
        replacement = self.inputs / 'replacement'
        replacement.write_bytes(b'B' * 32)
        owner = self.owner()
        original_read = os.read
        replaced = False

        def replace_after_read(descriptor, amount):
            nonlocal replaced
            chunk = original_read(descriptor, amount)
            if chunk and not replaced:
                replaced = True
                os.replace(replacement, path)
            return chunk

        with patch.object(census_tools.os, 'read', side_effect=replace_after_read):
            with self.assertRaisesRegex(census_tools.Incomplete, 'changed|replaced') as failure:
                owner.capture(str(path), 'fixture')
        owner.failure(failure.exception)
        row = json.loads((self.output / 'census.json').read_bytes())['paths'][str(path)]
        self.assertFalse(row['complete'])
        self.assertEqual((self.output / row['raw']['name']).read_bytes(), b'A' * 32)
        self.assertEqual(row['raw']['partial_sha256'], hashlib.sha256(b'A' * 32).hexdigest())

    def test_source_mutation_refuses_endpoint(self):
        path = self.inputs / 'source'
        path.write_bytes(b'original')
        owner = self.owner()
        owner.capture(str(path), 'profile-only-source')
        path.write_bytes(b'changed!')
        with self.assertRaisesRegex(census_tools.Incomplete, 'identity changed'):
            owner.reobserve(str(path))

    def test_caps_and_first_use_retains_bytes(self):
        path = self.inputs / 'oversized'
        with path.open('wb') as stream:
            stream.truncate(9)
        owner = self.owner(file_bytes=8)
        with self.assertRaisesRegex(census_tools.Incomplete, 'size cap') as failure:
            owner.capture(str(path), 'fixture')
        owner.failure(failure.exception)
        before = {p.relative_to(self.output): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
        with self.assertRaises(FileExistsError):
            self.owner()
        after = {p.relative_to(self.output): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
        self.assertEqual(after, before)
        self.assertEqual(list((self.output / 'raw').iterdir()), [])

    def test_member_growth_and_absence_change_refuse(self):
        missing = self.inputs / 'missing'
        owner = self.owner()
        owner.capture(str(missing), 'required-absence')
        missing.write_bytes(b'new')
        with self.assertRaises(census_tools.Incomplete):
            owner.reobserve(str(missing))
        with self.assertRaises(census_tools.Incomplete):
            owner.reobserve(str(self.inputs))

    def test_manifest_pin_duplicates_and_traversal(self):
        digest = hashlib.sha256(b'body').hexdigest()
        good = f'{digest}  path.py\n'.encode()
        pin = hashlib.sha256(good).hexdigest()
        self.assertEqual(census_tools.manifest_rows(good, pin, self.inputs, 1),
                         {str(self.inputs / 'path.py'): digest})
        with self.assertRaisesRegex(census_tools.Incomplete, 'digest differs'):
            census_tools.manifest_rows(good, '0' * 64, self.inputs, 1)
        for body, error in ((good + good, 'duplicate'), (f'{digest}  ../escape\n'.encode(), 'traversal')):
            with self.assertRaisesRegex(census_tools.Incomplete, error):
                census_tools.manifest_rows(body, hashlib.sha256(body).hexdigest(), self.inputs, 2)

    def test_authority_must_be_explicit_false(self):
        profile = {'application_enabled': False, 'import_inputs_reviewed': False,
                   'offline_reviewed': False, 'operations': {'holder': False, 'finite': False, 'recheck': False}}
        census_tools.disabled(profile)
        profile['operations']['holder'] = True
        with self.assertRaises(census_tools.Incomplete):
            census_tools.disabled(profile)

    def metadata_fixture(self, body):
        executable = self.inputs / 'owned-readelf'
        executable.write_text('#!/bin/sh\nexec /usr/bin/python3 -I -S -B -c ' + shlex.quote(body) + '\n')
        executable.chmod(0o700)
        subject = self.inputs / 'archived-subject'
        subject.write_bytes(b'owned metadata subject, never executed')
        owner = self.owner()
        owner.capture(str(subject), 'fixture-subject', eligible=True)
        return owner, executable, subject

    def test_metadata_output_cap_reaps_owned_group(self):
        owner, executable, subject = self.metadata_fixture('import os; os.write(1, b"x" * 2097153)')
        with patch.dict(census_tools.TOOLS, {'readelf': str(executable)}):
            with self.assertRaises(census_tools.Incomplete):
                owner.metadata('readelf', [str(subject)])
        run = owner.runs[0]
        self.assertEqual(run['streams']['stdout']['size'], 2097152)
        self.assertTrue(run['reaped'])
        self.assertTrue(run['group_closed'])
        self.assertFalse(run['complete'])
        self.assertIn('output cap', run['error'])

    def test_metadata_deadline_reaps_owned_group(self):
        owner, executable, subject = self.metadata_fixture('import time; time.sleep(30)')
        with patch.dict(census_tools.TOOLS, {'readelf': str(executable)}):
            with self.assertRaises(census_tools.Incomplete):
                owner.metadata('readelf', [str(subject)])
        run = owner.runs[0]
        self.assertTrue(run['reaped'])
        self.assertTrue(run['group_closed'])
        self.assertIn('deadline', run['error'])
        self.assertFalse(run['complete'])

    def test_metadata_success_is_only_raw_metadata(self):
        owner, executable, subject = self.metadata_fixture('import os; os.write(1, b"fixture-output\\n")')
        with patch.dict(census_tools.TOOLS, {'readelf': str(executable)}):
            run = owner.metadata('readelf', [str(subject)])
        self.assertTrue(run['reaped'])
        self.assertTrue(run['group_closed'])
        self.assertEqual(run['returncode'], 0)
        self.assertEqual((self.output / run['streams']['stdout']['name']).read_bytes(), b'fixture-output\n')
        self.assertEqual(run['argv'][1:7], ['--wide', '--file-header', '--program-headers', '--dynamic',
                         '--debug-dump=no-follow-links', '--debug-dump=do-not-use-debuginfod'])
        self.assertEqual(run['argv'][7], str(self.output / owner.regular_row(str(subject))['raw']['name']))

    def test_metadata_cancellation_drains_term_handler_prefixes(self):
        body = ('import os, signal, time\n'
                'def stop(*args):\n'
                ' os.write(1, b"term-stdout"); os.write(2, b"term-stderr"); raise SystemExit(0)\n'
                'signal.signal(signal.SIGTERM, stop)\n'
                'os.write(1, b"ready")\n'
                'time.sleep(30)\n')
        owner, executable, subject = self.metadata_fixture(body)
        with patch.dict(census_tools.TOOLS, {'readelf': str(executable)}):
            with self.assertRaises(census_tools.Incomplete):
                owner.metadata('readelf', [str(subject)])
        run = owner.runs[0]
        for name, expected in (('stdout', b'readyterm-stdout'), ('stderr', b'term-stderr')):
            raw = run['streams'][name]
            self.assertEqual((self.output / raw['name']).read_bytes(), expected)
            self.assertEqual(raw['partial_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(run['error'], 'metadata deadline')
        self.assertEqual(run['cleanup_errors'], [])
        self.assertTrue(run['pipes_drained'])
        self.assertTrue(run['reaped'])
        self.assertTrue(run['group_closed'])
        self.assertFalse(run['complete'])

    def test_metadata_cancellation_bounds_term_output(self):
        body = ('import os, signal, time\n'
                'def stop(*args):\n'
                ' os.write(2, b"z" * 262145)\n'
                'signal.signal(signal.SIGTERM, stop)\n'
                'os.write(1, b"ready")\n'
                'time.sleep(30)\n')
        owner, executable, subject = self.metadata_fixture(body)
        with patch.dict(census_tools.TOOLS, {'readelf': str(executable)}):
            with self.assertRaises(census_tools.Incomplete):
                owner.metadata('readelf', [str(subject)])
        run = owner.runs[0]
        raw = run['streams']['stderr']
        self.assertEqual((self.output / raw['name']).read_bytes(), b'z' * 262144)
        self.assertEqual(run['error'], 'metadata deadline')
        self.assertTrue(run['cleanup_output_truncated'])
        self.assertTrue(run['reaped'])
        self.assertTrue(run['group_closed'])
        self.assertFalse(run['complete'])

    def test_consumer_charges_count_overlap_and_hex_without_claiming_fit(self):
        paths = [self.inputs / name for name in ('a', 'b', 'profile', 'manifest')]
        for path, body in zip(paths, (b'abcd', b'xyz', b'p' * 10, b'm' * 20)):
            path.write_bytes(body)
        owner = self.owner()
        for path in paths:
            owner.capture(str(path), 'budget-fixture')
        a, b, profile_path, manifest_path = map(str, paths)
        profile = {'application_enabled': False, 'import_inputs_reviewed': False,
                   'offline_reviewed': False, 'operations': {'holder': False, 'finite': False, 'recheck': False},
                   'files': {a: hashlib.sha256(b'abcd').hexdigest()}, 'membership': {'fixture': ['a', 'b']}}
        projection = owner.consumer_charges(profile, [a, b], profile_path, manifest_path)
        self.assertEqual(projection['entry']['loop_bytes'], 11)
        self.assertEqual(projection['entry']['total_read_bytes'], 41)
        self.assertEqual(projection['offline']['union_bytes'], 37)
        self.assertEqual(projection['import_report']['document_hex_bytes'], 60)
        self.assertIsNone(projection['entry']['fits_current_limits'])
        self.assertIsNone(projection['import_report']['full_serialized_bytes'])


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, census_tools.interrupted)
    resource.setrlimit(resource.RLIMIT_CPU, (120, 122))
    resource.setrlimit(resource.RLIMIT_AS, (1073741824, 1073741824))
    resource.setrlimit(resource.RLIMIT_FSIZE, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    unittest.main()
