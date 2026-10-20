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
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time


CHECKOUT = Path('/home/zack/orca/workspaces/substrate-goal330-20261020/goal330-daemon-only-bootstrap')
OUTPUT = Path('/home/zack/.codex/orchestrate/vespiary-goal330/reviews/native-loading-tools-first')
MANIFEST = CHECKOUT / 'docs/dev/verify-runtime-20261020/native-api-inputs.sha256'
MANIFEST_SHA256 = '51b78d857b9fd0d88cc553e1cf80e7918c275e4ad6459b8829b6b2e806e773d9'
FILE_BYTES = 268435456
TOTAL_BYTES = 1073741824
RECORDS = 25000
JSON_BYTES = 8388608
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'HOME': '/home/zack', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC'}
TOOLS = {'readelf': '/usr/bin/readelf', 'cache': '/usr/sbin/ldconfig'}
AUTHORITIES = dict.fromkeys(('application', 'import', 'offline', 'holder', 'finite', 'recheck', 'native'), False)
GAPS = (
    'GIRepository glib2-2.88.4-1.fc44 compiled repository and library defaults lack build-correlated source',
    'glibc-2.43-9.fc44 default and hwcaps families lack build-correlated source',
    'openssl-3.5.9-1.fc44 compiled directories and complete configuration interpretation remain ungrounded',
    'maintained-tool process ownership is unproved; exact output grammar and bootstrap closure are not implemented',
    'complete corpus, pkgutil portions, actor graph and consumer serialization projection are not implemented',
)


class Incomplete(RuntimeError):
    pass


def identity(value):
    return {name: getattr(value, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def absolute(path):
    value = os.fspath(path)
    if not value.startswith('/') or '\x00' in value or len(os.fsencode(value)) > 4096:
        raise Incomplete('invalid absolute path')
    if value != '/' and any(part in ('', '.', '..') for part in value[1:].split('/')):
        raise Incomplete('noncanonical path')
    return value


def disabled(profile):
    for key in ('application_enabled', 'import_inputs_reviewed', 'offline_reviewed'):
        if profile.get(key) is not False:
            raise Incomplete('profile authority is not explicitly false')
    operations = profile.get('operations')
    if not isinstance(operations, dict) or set(operations) != {'holder', 'finite', 'recheck'}:
        raise Incomplete('unknown profile operations')
    if any(value is not False for value in operations.values()):
        raise Incomplete('operation authority is not explicitly false')


def manifest_rows(body, expected_digest, checkout, expected_rows):
    if hashlib.sha256(body).hexdigest() != expected_digest:
        raise Incomplete('source manifest digest differs from pin')
    rows = {}
    for line in body.decode('utf-8', errors='strict').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^\x00\r\n]+)', line)
        if not match:
            raise Incomplete('malformed source manifest')
        digest, name = match.groups()
        if not name.startswith('/'):
            if any(part in ('', '.', '..') for part in name.split('/')):
                raise Incomplete('source manifest traversal')
            name = str(checkout / name)
        name = absolute(name)
        if name in rows:
            raise Incomplete('duplicate source manifest path')
        rows[name] = digest
    if len(rows) != expected_rows:
        raise Incomplete('source manifest row count differs')
    return rows


class Census:
    def __init__(self, output, file_bytes=FILE_BYTES, total_bytes=TOTAL_BYTES, records=RECORDS):
        self.output = Path(absolute(output))
        self.paths = {}
        self.file_bytes = file_bytes
        self.total_bytes = total_bytes
        self.record_limit = records
        self.record_count = 0
        self.payload_bytes = 0
        self.json_bytes = 0
        self.started = time.monotonic()
        self.deadline = self.started + 117
        self.subject = None
        self.active = set()
        self.serial = 0
        self.runs = []
        self.child_cpu = 0
        self.tool_bytes = 0
        self._reserve_output()

    def _reserve_output(self):
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in self.output.parent.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_fd
                metadata = os.fstat(descriptor)
                if metadata.st_uid not in (0, os.getuid()) or metadata.st_mode & 0o022:
                    raise Incomplete('unsafe output ancestry')
            if os.fstat(descriptor).st_uid != os.getuid():
                raise Incomplete('output parent is not owned by operator')
            os.mkdir(self.output.name, 0o700, dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.document('intent.json', {'status': 'incomplete', 'authorities': AUTHORITIES,
                      'selection': 'unobserved', 'argv': sys.argv, 'started_ns': time.time_ns(),
                      'environment': ENVIRONMENT, 'interpreter': sys.executable,
                      'search': sys.path, 'version': sys.version,
                      'limits': {'file': self.file_bytes, 'payload': self.total_bytes,
                                 'records': self.record_limit, 'json': JSON_BYTES,
                                 'work_seconds': 117, 'cleanup_reservation_seconds': 3},
                      'gaps': GAPS})
        (self.output / 'raw').mkdir(mode=0o700)
        with (self.output / 'progress.jsonl').open('xb') as stream:
            stream.flush()
            os.fsync(stream.fileno())
        (self.output / 'tools').mkdir(mode=0o700)

    def check(self):
        if time.monotonic() >= self.deadline:
            raise Incomplete('work deadline exhausted')

    def charge(self, amount):
        if self.record_count + amount > self.record_limit:
            raise Incomplete('path or membership record cap')
        self.record_count += amount

    def document(self, name, value):
        with (self.output / name).open('xb') as stream:
            self._json_write(stream, value, JSON_BYTES)
        descriptor = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def progress(self, path):
        with (self.output / 'progress.jsonl').open('ab') as stream:
            self._json_write(stream, {'path': path, 'observation': self.paths[path]}, JSON_BYTES // 2)

    def _json_write(self, stream, value, limit):
        encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        try:
            for chunk in encoder.iterencode(value):
                body = chunk.encode('ascii')
                if self.json_bytes + len(body) + 1 > limit:
                    raise Incomplete('generated JSON cap')
                self.json_bytes += len(body)
                stream.write(body)
            stream.write(b'\n')
            self.json_bytes += 1
        finally:
            stream.flush()
            os.fsync(stream.fileno())

    def directory_fd(self, path, depth=0):
        if depth > 40:
            raise Incomplete('link depth cap')
        if path == '/':
            descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        else:
            row = self.capture(path, 'ancestry')
            if row['kind'] == 'symlink':
                return self.directory_fd(row['target_path'], depth + 1)
            if row['kind'] != 'directory':
                raise Incomplete('parent is not a directory')
            parent = self.directory_fd(str(Path(path).parent), depth + 1)
            try:
                descriptor = os.open(Path(path).name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=parent)
            finally:
                os.close(parent)
        if path in self.paths and identity(os.fstat(descriptor)) != self.paths[path]['before']:
            os.close(descriptor)
            raise Incomplete('directory descriptor changed')
        return descriptor

    def capture(self, path, reason, eligible=False):
        path = absolute(path)
        self.check()
        self.subject = path
        if path != '/' and '/' not in self.paths:
            self.capture('/', 'ancestry')
        if path in self.active or len(self.active) >= 40:
            raise Incomplete('path or symlink cycle')
        if path in self.paths:
            row = self.paths[path]
            self.reobserve(path)
            if reason not in row['reasons']:
                self.charge(1)
                row['reasons'].append(reason)
            row['eligible'] = row['eligible'] or eligible
            if row['kind'] == 'symlink' and eligible:
                self.capture(row['target_path'], 'link:' + path, eligible=True)
            return row
        self.active.add(path)
        try:
            parent = self.directory_fd(str(Path(path).parent)) if path != '/' else os.open(
                '/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                name = Path(path).name if path != '/' else '.'
                self.subject = path
                self.charge(1)
                row = {'reasons': [reason], 'eligible': eligible, 'complete': False}
                self.paths[path] = row
                try:
                    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    if path == '/':
                        raise
                    row.update(kind='absent', parent=str(Path(path).parent), errno=2)
                    parent_row = self.paths[row['parent']]
                    for _ in range(40):
                        if parent_row['kind'] != 'symlink':
                            break
                        parent_row = self.paths[parent_row['target_path']]
                    if name in parent_row['names']:
                        raise Incomplete('absence contradicts parent membership')
                else:
                    row['before'] = identity(before)
                    if before.st_uid not in (0, os.getuid()) or (
                            not stat.S_ISLNK(before.st_mode) and before.st_mode & 0o022):
                        raise Incomplete('unexpected owner or writable input')
                    if stat.S_ISLNK(before.st_mode):
                        target = os.readlink(name, dir_fd=parent)
                        if len(os.fsencode(target)) > 4096:
                            raise Incomplete('link target cap')
                        next_path = os.path.normpath(os.path.join(str(Path(path).parent), target))
                        row.update(kind='symlink', target=target, target_path=next_path)
                        if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != row['before']:
                            raise Incomplete('link changed')
                        self.capture(next_path, 'link:' + path, eligible)
                    elif stat.S_ISDIR(before.st_mode):
                        row['kind'] = 'directory'
                        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                             dir_fd=parent)
                        try:
                            if identity(os.fstat(descriptor)) != row['before']:
                                raise Incomplete('directory replaced')
                            names = []
                            with os.scandir(descriptor) as entries:
                                for entry in entries:
                                    self.check()
                                    self.charge(1)
                                    names.append(entry.name)
                            row['names'] = sorted(names)
                            if identity(os.fstat(descriptor)) != row['before']:
                                raise Incomplete('directory changed')
                        finally:
                            os.close(descriptor)
                    elif stat.S_ISREG(before.st_mode):
                        row['kind'] = 'regular'
                        self._regular(parent, name, row)
                    else:
                        raise Incomplete('unsupported filesystem type')
                    if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != row['before']:
                        raise Incomplete('input pathname replaced')
                row['complete'] = True
                self.progress(path)
                return row
            finally:
                os.close(parent)
        finally:
            self.active.remove(path)

    def _regular(self, parent, name, row):
        size = row['before']['st_size']
        if size > self.file_bytes or size > self.total_bytes - self.payload_bytes:
            raise Incomplete('regular input size cap')
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        digest = hashlib.sha256()
        self.serial += 1
        raw = {'name': f'raw/{self.serial:06d}.bin', 'size': 0, 'partial_sha256': digest.hexdigest()}
        row['raw'] = raw
        try:
            self.progress(self.subject)
            if identity(os.fstat(descriptor)) != row['before']:
                raise Incomplete('regular descriptor replaced')
            with (self.output / raw['name']).open('xb') as archive:
                try:
                    while raw['size'] < size:
                        self.check()
                        chunk = os.read(descriptor, min(1048576, size - raw['size']))
                        if not chunk:
                            raise Incomplete('regular input shrank')
                        archive.write(chunk)
                        digest.update(chunk)
                        raw['size'] += len(chunk)
                        self.payload_bytes += len(chunk)
                        raw['partial_sha256'] = digest.hexdigest()
                    if os.read(descriptor, 1):
                        raise Incomplete('regular input grew')
                    if identity(os.fstat(descriptor)) != row['before']:
                        raise Incomplete('regular input changed')
                finally:
                    archive.flush()
                    os.fsync(archive.fileno())
            raw['sha256'] = raw.pop('partial_sha256')
        finally:
            os.close(descriptor)

    def reobserve(self, path):
        row = self.paths[path]
        if not row['complete']:
            raise Incomplete('incomplete observation reused')
        parent = self.directory_fd(str(Path(path).parent)) if path != '/' else os.open(
            '/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            name = Path(path).name if path != '/' else '.'
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if row['kind'] != 'absent':
                    raise Incomplete('input disappeared')
                return
            if row['kind'] == 'absent' or identity(current) != row['before']:
                raise Incomplete('input identity changed')
            if row['kind'] == 'symlink' and os.readlink(name, dir_fd=parent) != row['target']:
                raise Incomplete('link target changed')
            if row['kind'] == 'directory':
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=parent)
                try:
                    names = []
                    with os.scandir(descriptor) as entries:
                        for entry in entries:
                            self.check()
                            if len(names) >= self.record_limit:
                                raise Incomplete('reobservation membership cap')
                            names.append(entry.name)
                    if sorted(names) != row['names'] or identity(os.fstat(descriptor)) != row['before']:
                        raise Incomplete('directory membership changed')
                finally:
                    os.close(descriptor)
        finally:
            os.close(parent)

    def regular_row(self, path):
        for _ in range(40):
            row = self.paths[path]
            if row['kind'] != 'symlink':
                if row['kind'] != 'regular' or not row['complete']:
                    raise Incomplete('required regular input unavailable')
                return row
            path = row['target_path']
        raise Incomplete('link depth cap')

    def small_body(self, path):
        row = self.regular_row(path)
        if row['raw']['size'] > 1048576:
            raise Incomplete('source document cap')
        body = (self.output / row['raw']['name']).read_bytes()
        if hashlib.sha256(body).hexdigest() != row['raw']['sha256']:
            raise Incomplete('archived source document changed')
        return body

    def source_inputs(self):
        self.capture(str(MANIFEST), 'fixed-source')
        rows = manifest_rows(self.small_body(str(MANIFEST)), MANIFEST_SHA256, CHECKOUT, 31)
        for path, digest in rows.items():
            self.capture(path, 'manifest')
            if self.regular_row(path)['raw']['sha256'] != digest:
                raise Incomplete('source input digest differs from manifest')
        profile = str(MANIFEST.with_name('native-python-profile.json'))
        parsed = json.loads(self.small_body(profile))
        disabled(parsed)
        if list(sys.path) != parsed['stdlib_search']:
            raise Incomplete('isolated interpreter search differs from reviewed profile')
        self.capture(str(Path(__file__)), 'census-source')

    def metadata(self, operation, subjects):
        if any(not run['reaped'] or not run['group_closed'] for run in self.runs):
            raise Incomplete('previous metadata group closure is unknown')
        if operation not in TOOLS or not 1 <= len(subjects) <= (16 if operation == 'readelf' else 1):
            raise Incomplete('unknown metadata operation or subject count')
        used = resource.getrusage(resource.RUSAGE_SELF)
        remaining = int(120 - used.ru_utime - used.ru_stime - self.child_cpu - 3)
        if len(self.runs) >= 256 or remaining < 1 or time.monotonic() + 8 >= self.deadline:
            raise Incomplete('metadata admission reserves CPU and cleanup')
        executable = TOOLS[operation]
        self.capture(executable, 'acquisition-tool', eligible=True)
        tool = self.regular_row(executable)['raw'].copy()
        archived = [str(self.output / self.regular_row(path)['raw']['name']) for path in subjects]
        argv = ([executable, '--wide', '--file-header', '--program-headers', '--dynamic',
                 '--debug-dump=no-follow-links', '--debug-dump=do-not-use-debuginfod', *archived]
                if operation == 'readelf' else [executable, '--print-cache', '-C', *archived])
        run = {'argv': argv, 'subjects': list(subjects), 'tool': tool, 'complete': False,
               'scope': 'raw-metadata-only', 'grammar_validated': False, 'bootstrap_closed': False,
               'group_closed': False, 'reaped': False, 'returncode': None, 'streams': {}}
        self.runs.append(run)
        number = len(self.runs)
        self.document(f'tools/{number:04d}.intent.json', run)
        streams = {}
        selector = selectors.DefaultSelector()
        child = None
        error = None
        started = time.monotonic()

        def child_limits():
            resource.setrlimit(resource.RLIMIT_CPU, (min(4, remaining), min(5, remaining)))
            resource.setrlimit(resource.RLIMIT_AS, (536870912, 536870912))
            resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_BYTES, FILE_BYTES))
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))

        try:
            for name in ('stdout', 'stderr'):
                raw = {'name': f'tools/{number:04d}.{name}.raw', 'size': 0,
                       'partial_sha256': hashlib.sha256(b'').hexdigest()}
                run['streams'][name] = raw
                streams[name] = ((self.output / raw['name']).open('xb'), hashlib.sha256())
            self.capture(executable, 'tool-before-exec', eligible=True)
            used = resource.getrusage(resource.RUSAGE_SELF)
            remaining = int(120 - used.ru_utime - used.ru_stime - self.child_cpu - 3)
            if remaining < 1 or time.monotonic() + 8 >= self.deadline:
                raise Incomplete('metadata spawn has insufficient CPU or cleanup reservation')
            run['cpu_soft_hard_seconds'] = [min(4, remaining), min(5, remaining)]
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={**ENVIRONMENT, 'DEBUGINFOD_URLS': ''}, close_fds=True,
                                     start_new_session=True, preexec_fn=child_limits)
            run['pid'] = child.pid
            run['pgid'] = child.pid
            self.document(f'tools/{number:04d}.spawn.json', run)
            for name, pipe in (('stdout', child.stdout), ('stderr', child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            deadline = min(started + 5, self.deadline - 3)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise Incomplete('metadata deadline')
                for key, _mask in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                    name = key.data
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    raw = run['streams'][name]
                    cap = 2097152 if name == 'stdout' else 262144
                    available = min(cap - raw['size'], 33554432 - self.tool_bytes,
                                    self.total_bytes - self.payload_bytes)
                    kept = chunk[:max(0, available)]
                    stream, digest = streams[name]
                    stream.write(kept)
                    digest.update(kept)
                    raw['size'] += len(kept)
                    self.tool_bytes += len(kept)
                    self.payload_bytes += len(kept)
                    raw['partial_sha256'] = digest.hexdigest()
                    if len(kept) != len(chunk):
                        raise Incomplete('metadata output cap')
            while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= deadline:
                    raise Incomplete('metadata exit deadline')
                time.sleep(0.01)
        except BaseException as failure:
            error = failure
        finally:
            if child is not None:
                cleanup_end = min(time.monotonic() + 3, self.deadline)
                for signum in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(child.pid, signum)
                    except ProcessLookupError:
                        pass
                    if signum == signal.SIGTERM and error is not None:
                        grace = min(time.monotonic() + 1, cleanup_end)
                        while time.monotonic() < grace:
                            time.sleep(min(0.02, grace - time.monotonic()))
                while time.monotonic() < cleanup_end:
                    pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                    if pid == child.pid:
                        self.child_cpu += usage.ru_utime + usage.ru_stime
                        run['child_cpu_seconds'] = usage.ru_utime + usage.ru_stime
                        child.returncode = os.waitstatus_to_exitcode(status)
                        run.update(reaped=True, returncode=child.returncode)
                        break
                    time.sleep(0.01)
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    run['group_closed'] = True
                for pipe in (child.stdout, child.stderr):
                    pipe.close()
            selector.close()
            for stream, _digest in streams.values():
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
            run['elapsed_seconds'] = time.monotonic() - started
            run['error'] = None if error is None else str(error)
            self.document(f'tools/{number:04d}.closed.json', run)
        self.capture(executable, 'tool-after-exec', eligible=True)
        if self.regular_row(executable)['raw'] != tool:
            raise Incomplete('executed metadata tool changed')
        if error is not None or not run['reaped'] or not run['group_closed'] or run['returncode'] != 0:
            raise Incomplete('metadata failed or positive child closure unavailable') from error
        for raw in run['streams'].values():
            raw['sha256'] = raw.pop('partial_sha256')
        run['complete'] = True
        self.document(f'tools/{number:04d}.complete.json', run)
        return run

    def consumer_charges(self, profile, source_paths, profile_path, manifest_path):
        disabled(profile)
        sizes = {path: self.regular_row(path)['raw']['size'] for path in
                 set(profile['files']) | set(source_paths) | {profile_path, manifest_path}}
        profile_bytes = sizes[profile_path]
        manifest_bytes = sizes[manifest_path]
        entry_loop = sum(sizes[path] for path in profile['files']) + sum(sizes[path] for path in source_paths)
        largest = max(sizes.values(), default=0)
        membership_names = sum(len(names) for names in profile['membership'].values())
        largest_membership = max((len(names) for names in profile['membership'].values()), default=0)
        entry_exceeds = (entry_loop > 536870912 or largest > 134217728 or
                         largest_membership > 4096 or profile_bytes > 1048576 or manifest_bytes > 1048576)
        union = sum(sizes.values())
        offline_exceeds = (union > 536870912 or largest > 134217728 or len(sizes) > 4096 or
                           largest_membership > 4096 or profile_bytes > 1048576 or manifest_bytes > 1048576)
        return {'status': 'incomplete', 'authorities': AUTHORITIES, 'selection': 'unobserved',
                'basis': 'exact archived sizes for the declared profile and source manifest only',
                'entry': {'loop_bytes': entry_loop, 'document_bytes': profile_bytes + manifest_bytes,
                          'total_read_bytes': entry_loop + profile_bytes + manifest_bytes,
                          'fits_current_limits': False if entry_exceeds else None},
                'offline': {'union_bytes': union, 'union_paths': len(sizes),
                            'fits_current_limits': False if offline_exceeds else None},
                'largest_file_bytes': largest, 'membership_names': membership_names,
                'largest_membership': largest_membership,
                'import_report': {'document_hex_bytes': 2 * (profile_bytes + manifest_bytes),
                                  'source_buffer_hex_bytes': None, 'full_serialized_bytes': None},
                'snapshot_map_serialized_bytes': None, 'producer_output_bytes': None,
                'proposed_profile_serialized_bytes': None,
                'remaining_gates': ['complete corpus and candidate closure', 'proposed profile serialization',
                                    'actual snapshot map and source-buffer report serialization',
                                    'matching entry and offline membership/JSON and producer limits']}

    def failure(self, error):
        self.document('census.json', {'status': 'incomplete', 'paths': self.paths,
                      'authorities': AUTHORITIES, 'selection': 'unobserved'})
        self.document('failure.json', {'status': 'incomplete', 'category': type(error).__name__,
                      'error': str(error), 'subject': self.subject, 'gaps': GAPS,
                      'payload_bytes': self.payload_bytes, 'records': self.record_count,
                      'tool_runs': self.runs, 'child_cpu_seconds': self.child_cpu,
                      'elapsed_seconds': time.monotonic() - self.started,
                      'authorities': AUTHORITIES, 'selection': 'unobserved'})


def interrupted(_signum, _frame):
    raise Incomplete('parent interrupted')


def main():
    if len(sys.argv) != 1:
        raise Incomplete('census accepts no arguments')
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise Incomplete('isolated no-site no-bytecode interpreter required')
    if set(os.environ) != set(ENVIRONMENT) or any(os.environ[key] != value for key, value in ENVIRONMENT.items()):
        raise Incomplete('fixed scrubbed environment required')
    for kind, limits in ((resource.RLIMIT_CPU, (120, 122)), (resource.RLIMIT_AS, (TOTAL_BYTES, TOTAL_BYTES)),
                         (resource.RLIMIT_FSIZE, (FILE_BYTES, FILE_BYTES)), (resource.RLIMIT_NOFILE, (128, 128))):
        resource.setrlimit(kind, limits)
    signal.signal(signal.SIGTERM, interrupted)
    census = Census(OUTPUT)
    try:
        raise Incomplete('; '.join(GAPS))
    except Exception as error:
        census.failure(error)
        return 1


if __name__ == '__main__':
    sys.exit(main())
