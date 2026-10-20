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
    'GIRepository build-correlated defaults await fixed declarations and namespace/library closure',
    'glibc build-correlated defaults await RPATH, cache, environment and hwcaps candidate closure',
    'OpenSSL build-correlated defaults await complete contextual configuration and provider closure',
    'maintained-tool process ownership and authored text grammars are unproved; bootstrap closure is not implemented',
    'supplied corpus and projection await proof; actor graph, runtime census and profile publication remain gated',
)


class Incomplete(RuntimeError):
    pass


class Unsupported(Incomplete):
    def __init__(self, family, path, detail):
        self.family = family
        self.path = path
        super().__init__(f'{family}: {path}: {detail}')


def consumer_json(value):
    return json.dumps(value, sort_keys=True, allow_nan=False).encode('utf-8')


def producer_size(value):
    return len(json.dumps(value, sort_keys=True, ensure_ascii=True,
                          separators=(',', ':'), allow_nan=False).encode('ascii')) + 1


def serialized_size(value, limit):
    size = 0
    for chunk in json.JSONEncoder(sort_keys=True, allow_nan=False).iterencode(value):
        size += len(chunk.encode('utf-8'))
        if size > limit:
            raise Incomplete('consumer serialization cap')
    return size


def limit_charge(amount, cap):
    return {'bytes_or_records': amount, 'cap': cap, 'excess': max(0, amount - cap),
            'fits': amount <= cap}


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


def cache_facts(body, archive):
    if not body.endswith(b'\n'):
        raise Incomplete('truncated cache output')
    lines = body.decode('ascii', errors='strict').splitlines()
    if not lines or lines[0] != f'{len(lines) - 3} libs found in cache `{archive}\'':
        raise Incomplete('unknown cache header or row count')
    if not re.fullmatch(r'Cache generated by: ldconfig \([^\r\n]+\) stable release version 2\.43', lines[-2]):
        raise Incomplete('unknown cache producer')
    if not re.fullmatch(r'File size: [0-9]+ bytes\.', lines[-1]):
        raise Incomplete('unknown cache trailer')
    rows = []
    for line in lines[1:-2]:
        match = re.fullmatch(r'\t([^ /\t()]+) \((libc6(?:,x86-64)?)(?:, hwcap: "([A-Za-z0-9_-]+)")?\) => (/[^\r\n\t ]+)', line)
        if not match:
            raise Incomplete('unknown cache row or ABI')
        soname, abi, hwcap, path = match.groups()
        rows.append({'soname': soname, 'abi': abi, 'hwcap': hwcap, 'path': absolute(path)})
    return rows


def elf_facts(body, archives):
    text = body.decode('ascii', errors='strict')
    if not text.endswith('\n') or '\x00' in text:
        raise Incomplete('truncated readelf output')
    if len(archives) == 1 and not text.startswith('\nFile: ') and not text.startswith('File: '):
        portions = [(archives[0], text)]
    else:
        pieces = re.split(r'(?:\A|\n)File: ([^\n]+)\n', text)
        if pieces[0].strip() or len(pieces) != 1 + 2 * len(archives):
            raise Incomplete('readelf subject framing')
        portions = list(zip(pieces[1::2], pieces[2::2]))
    if [name for name, _ in portions] != list(archives):
        raise Incomplete('readelf subject mismatch')
    facts = []
    for archive, portion in portions:
        lines = [line for line in portion.splitlines() if line.strip()]
        if not lines or lines.pop(0) != 'ELF Header:':
            raise Incomplete('unknown readelf header')
        header = {}
        fields = ('Magic', 'Class', 'Data', 'Version', 'OS/ABI', 'ABI Version', 'Type', 'Machine',
                  'Version', 'Entry point address', 'Start of program headers', 'Start of section headers',
                  'Flags', 'Size of this header', 'Size of program headers', 'Number of program headers',
                  'Size of section headers', 'Number of section headers', 'Section header string table index')
        for field in fields:
            if not lines:
                raise Incomplete('truncated readelf header')
            match = re.fullmatch(r'  ' + re.escape(field) + r':\s+([^\r\n]+)', lines.pop(0))
            if not match:
                raise Incomplete('unknown readelf header field')
            if field == 'Version' and match[1].strip() != ('0x1' if field in header else '1 (current)'):
                raise Incomplete('unknown ELF version field')
            header[field] = match[1].strip()
        for field, pattern in (
                ('Entry point address', r'0x[0-9a-f]+'),
                ('Start of program headers', r'[0-9]+ \(bytes into file\)'),
                ('Start of section headers', r'[0-9]+ \(bytes into file\)'),
                ('Size of this header', r'64 \(bytes\)'),
                ('Size of program headers', r'56 \(bytes\)'),
                ('Size of section headers', r'64 \(bytes\)'),
                ('Number of section headers', r'[0-9]+'),
                ('Section header string table index', r'[0-9]+')):
            if not re.fullmatch(pattern, header[field]):
                raise Incomplete('unsupported ELF header number')
        if (header['Class'] != 'ELF64' or header['Data'] != "2's complement, little endian" or
                header['Machine'] != 'Advanced Micro Devices X86-64' or
                not re.fullmatch(r'(EXEC|DYN) \([^()]+\)', header['Type'])):
            raise Incomplete('unsupported ELF class, encoding, machine or type')
        if (not re.fullmatch(r'7f 45 4c 46 02 01 01(?: [0-9a-f]{2}){9}', header['Magic']) or
                header['Version'] != '0x1' or header['Flags'] != '0x0' or
                header['OS/ABI'] not in {'UNIX - System V', 'UNIX - GNU'} or header['ABI Version'] != '0'):
            raise Incomplete('unsupported ELF header values')
        count = header['Number of program headers']
        if not re.fullmatch(r'[1-9][0-9]*', count) or int(count) > 1024:
            raise Incomplete('unsupported ELF program count')
        if lines[:2] != ['Program Headers:', '  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align']:
            raise Incomplete('unknown readelf program header grammar')
        del lines[:2]
        result = {'archive': archive, 'class': header['Class'], 'machine': header['Machine'],
                  'type': header['Type'].split()[0], 'interpreter': None, 'needed': [],
                  'soname': None, 'rpath': None, 'runpath': None, 'dynamic_flags': []}
        types = {'PHDR', 'INTERP', 'LOAD', 'DYNAMIC', 'NOTE', 'TLS', 'GNU_EH_FRAME',
                 'GNU_STACK', 'GNU_RELRO', 'GNU_PROPERTY'}
        for _ in range(int(count)):
            if not lines:
                raise Incomplete('truncated readelf program headers')
            match = re.fullmatch(r'  ([A-Z_]+)\s+(0x[0-9a-f]+\s+){5}[RWE ]+\s+0x[0-9a-f]+', lines.pop(0))
            if not match or match[1] not in types:
                raise Incomplete('unknown readelf program type')
            if match[1] == 'INTERP':
                interp = re.fullmatch(r'      \[Requesting program interpreter: (/[^\[\]\r\n]+)\]', lines.pop(0)) if lines else None
                if not interp or result['interpreter'] is not None:
                    raise Incomplete('unknown or repeated interpreter')
                result['interpreter'] = absolute(interp[1])
        if lines and lines[0] == ' Section to Segment mapping:':
            del lines[0]
            if not lines or lines.pop(0).strip() != 'Segment Sections...':
                raise Incomplete('unknown readelf section map')
            while lines and re.fullmatch(r'   [0-9]{2,}\s+[^\r\n]*', lines[0]):
                del lines[0]
        if lines == ['There is no dynamic section in this file.']:
            facts.append(result)
            continue
        dynamic = re.fullmatch(r'Dynamic section at offset 0x[0-9a-f]+ contains ([0-9]+) entries:', lines.pop(0)) if lines else None
        if not dynamic or not lines or lines.pop(0).strip() != 'Tag        Type                         Name/Value':
            raise Incomplete('unknown readelf dynamic header')
        if int(dynamic[1]) != len(lines):
            raise Incomplete('readelf dynamic count mismatch')
        scalar = {'INIT', 'FINI', 'INIT_ARRAY', 'INIT_ARRAYSZ', 'FINI_ARRAY', 'FINI_ARRAYSZ',
                  'GNU_HASH', 'HASH', 'STRTAB', 'SYMTAB', 'STRSZ', 'SYMENT', 'DEBUG', 'PLTGOT',
                  'PLTRELSZ', 'PLTREL', 'JMPREL', 'RELA', 'RELASZ', 'RELAENT', 'RELACOUNT',
                  'RELR', 'RELRSZ', 'RELRENT', 'VERNEED', 'VERNEEDNUM', 'VERSYM', 'VERDEF', 'VERDEFNUM'}
        seen = set()
        for index, line in enumerate(lines):
            match = re.fullmatch(r' 0x[0-9a-f]+ \(([A-Z0-9_]+)\)\s+(.+)', line)
            if not match:
                raise Incomplete('unknown readelf dynamic row')
            tag, value = match.groups()
            if tag != 'NEEDED' and tag in seen:
                raise Incomplete('repeated readelf dynamic field')
            seen.add(tag)
            if tag in {'NEEDED', 'SONAME', 'RPATH', 'RUNPATH'}:
                label = {'NEEDED': 'Shared library', 'SONAME': 'Library soname',
                         'RPATH': 'Library rpath', 'RUNPATH': 'Library runpath'}[tag]
                name = re.fullmatch(re.escape(label) + r': \[([^\[\]\r\n]+)\]', value)
                if not name:
                    raise Incomplete('unknown readelf path value')
                if tag == 'NEEDED':
                    result['needed'].append(name[1])
                elif result[tag.lower()] is not None:
                    raise Incomplete('repeated readelf path field')
                else:
                    result[tag.lower()] = name[1]
            elif tag in {'FLAGS', 'FLAGS_1'}:
                flags = value.removeprefix('Flags: ').split()
                allowed = {'ORIGIN', 'BIND_NOW', 'STATIC_TLS'} if tag == 'FLAGS' else {'NOW', 'NODELETE', 'ORIGIN', 'PIE'}
                if not flags or not set(flags) <= allowed:
                    raise Incomplete('unknown ELF dynamic flags')
                result['dynamic_flags'].append([tag, flags])
            elif tag == 'NULL':
                if index != len(lines) - 1 or value != '0x0':
                    raise Incomplete('unknown ELF dynamic terminator')
            elif tag not in scalar or not re.fullmatch(r'(0x[0-9a-f]+|[0-9]+(?: \(bytes\))?|RELA)', value):
                raise Incomplete('unsupported ELF dynamic mechanism')
        if not lines or '(NULL)' not in lines[-1]:
            raise Incomplete('missing ELF dynamic terminator')
        facts.append(result)
    return facts


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
        amount = producer_size(value)
        if amount > limit or self.json_bytes + amount > JSON_BYTES:
            raise Incomplete('generated JSON cap')
        encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        try:
            for chunk in encoder.iterencode(value):
                body = chunk.encode('ascii')
                if self.json_bytes + len(body) + 1 > JSON_BYTES:
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

    def capture(self, path, reason, eligible=False, candidate=False, allowed_roots=(), ordinary=False):
        path = absolute(path)
        if allowed_roots and not any(path == root or path.startswith(root + '/') for root in allowed_roots):
            raise Unsupported('corpus-destination', path, 'outside declared ordinary roots')
        self.check()
        self.subject = path
        if path != '/' and '/' not in self.paths:
            self.capture('/', 'ancestry')
        if path in self.active or len(self.active) >= 40:
            raise Incomplete('path or symlink cycle')
        if path in self.paths:
            row = self.paths[path]
            if ordinary and row.get('kind') == 'symlink':
                raise Unsupported('corpus-ancestor-link', path, 'linked ancestors are unsupported')
            self.reobserve(path)
            if reason not in row['reasons']:
                self.charge(1)
                row['reasons'].append(reason)
            row['eligible'] = row['eligible'] or eligible
            row['candidate'] = row.get('candidate', False) or candidate
            if row['kind'] == 'symlink' and (eligible or candidate or allowed_roots):
                self.capture(row['target_path'], 'link:' + path, eligible, candidate, allowed_roots)
            return row
        self.active.add(path)
        try:
            if path != '/':
                parent_path = str(Path(path).parent)
                parent_row = self.capture(parent_path, 'ancestry', ordinary=ordinary or bool(allowed_roots))
                if parent_row['kind'] == 'absent':
                    self.charge(1)
                    row = {'reasons': [reason], 'eligible': eligible, 'candidate': candidate,
                           'complete': True, 'kind': 'absent', 'parent': parent_path,
                           'errno': 2, 'absent_ancestor': parent_row.get('absent_ancestor', parent_path)}
                    self.paths[path] = row
                    self.progress(path)
                    return row
            parent = self.directory_fd(str(Path(path).parent)) if path != '/' else os.open(
                '/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                name = Path(path).name if path != '/' else '.'
                self.subject = path
                self.charge(1)
                row = {'reasons': [reason], 'eligible': eligible, 'candidate': candidate, 'complete': False}
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
                        if ordinary:
                            raise Unsupported('corpus-ancestor-link', path, 'linked ancestors are unsupported')
                        if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != row['before']:
                            raise Incomplete('link changed')
                        self.capture(next_path, 'link:' + path, eligible, candidate, allowed_roots)
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
        if 'absent_ancestor' in row:
            self.reobserve(row['absent_ancestor'])
            return
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

    def resolved(self, path):
        path = absolute(path)
        for _ in range(40):
            row = self.paths[path]
            if not row['complete']:
                raise Incomplete('incomplete observation reused')
            if row['kind'] != 'symlink':
                return path, row
            path = row['target_path']
        raise Incomplete('link depth cap')

    def corpus_tree(self, path, reason, excluded=(), extension_suffixes=(), ancestors=(), allowed_roots=()):
        path = absolute(path)
        allowed_roots = allowed_roots or (path,)
        self.capture(path, reason, candidate=path.endswith(tuple(extension_suffixes)), allowed_roots=allowed_roots)
        target, observed = self.resolved(path)
        if observed['kind'] == 'absent':
            raise Unsupported('required-corpus', path, 'missing required tree member')
        if observed['kind'] == 'regular':
            return
        node = (observed['before']['st_dev'], observed['before']['st_ino'])
        if node in ancestors or len(ancestors) >= 40:
            raise Unsupported('corpus-cycle', path, 'recursive directory alias')
        if path in excluded or target in excluded:
            self.capture(path, 'separate-package-domain')
            return
        for name in observed['names']:
            self.corpus_tree(str(Path(path) / name), reason, excluded, extension_suffixes,
                             (*ancestors, node), allowed_roots)

    def interpreter_corpus(self, search, package_boundaries, extension_suffixes):
        if not search or not extension_suffixes:
            raise Unsupported('interpreter-corpus', '', 'missing search or extension suffix declarations')
        if len(set(search)) != len(search) or len(set(extension_suffixes)) != len(extension_suffixes):
            raise Unsupported('interpreter-corpus', '', 'duplicate search or suffix declaration')
        directories = 0
        for path in search:
            self.capture(path, 'interpreter-search', allowed_roots=tuple(search))
            _target, row = self.resolved(path)
            if row['kind'] == 'absent':
                continue
            if row['kind'] != 'directory':
                raise Unsupported('zip-search', path, 'present archive requires bounded ZIP metadata support')
            directories += 1
            self.corpus_tree(path, 'stdlib-corpus', package_boundaries, extension_suffixes)
        if not directories:
            raise Unsupported('interpreter-corpus', '', 'no present interpreter corpus directory')

    def supplied_interpreter(self, record, source, digest):
        self.capture(source, 'supplied-interpreter-record')
        if self.regular_row(source)['raw']['sha256'] != digest:
            raise Unsupported('interpreter-record', source, 'source digest differs')
        if json.loads(self.small_body(source)) != record:
            raise Unsupported('interpreter-record', source, 'supplied record differs from archived source')
        fields = {'executable', 'prefix', 'base_prefix', 'version', 'search', 'builtins',
                  'frozen', 'extension_suffixes', 'identities', 'executable_sha256', 'declarations_complete'}
        if not isinstance(record, dict) or set(record) != fields or record['declarations_complete'] is not True:
            raise Unsupported('interpreter-record', source, 'explicit complete declarations required')
        if not isinstance(record['version'], str) or not record['version']:
            raise Unsupported('interpreter-record', source, 'missing version')
        for key in ('search', 'builtins', 'frozen', 'extension_suffixes'):
            values = record[key]
            if (not isinstance(values, list) or not values or
                    any(not isinstance(value, str) or not value for value in values) or
                    len(set(values)) != len(values)):
                raise Unsupported('interpreter-record', source, 'invalid or duplicate ' + key)
        if set(record['builtins']) & set(record['frozen']):
            raise Unsupported('interpreter-record', source, 'built-in and frozen declarations overlap')
        if any(not re.fullmatch(r'\.[A-Za-z0-9_.-]+\.so|\.so', suffix)
               for suffix in record['extension_suffixes']):
            raise Unsupported('interpreter-record', source, 'unsupported extension suffix')
        paths = {absolute(record[key]) for key in ('executable', 'prefix', 'base_prefix')}
        paths.update(absolute(path) for path in record['search'])
        if not isinstance(record['identities'], dict) or set(record['identities']) != paths:
            raise Unsupported('interpreter-record', source, 'exact path identities required')
        for path in sorted(paths):
            self.capture(path, 'supplied-interpreter-identity')
            _target, row = self.resolved(path)
            observed = None if row['kind'] == 'absent' else row['before']
            if observed != record['identities'][path]:
                raise Unsupported('interpreter-record', path, 'identity differs from supplied source')
        executable = self.regular_row(record['executable'])
        if executable['raw']['sha256'] != record['executable_sha256']:
            raise Unsupported('interpreter-record', record['executable'], 'executable digest differs')
        if not executable['before']['st_mode'] & 0o111:
            raise Unsupported('interpreter-record', record['executable'], 'executable mode required')
        for key in ('prefix', 'base_prefix'):
            if self.resolved(record[key])[1]['kind'] != 'directory':
                raise Unsupported('interpreter-record', record[key], 'prefix directory required')
        return {'basis': 'supplied-source-correlated-record', 'host_observed': False,
                'record': record, 'source': source, 'sha256': digest, 'authorities': AUTHORITIES}

    def package_corpus(self, modules, distributions, extension_suffixes):
        names = [name for name, _path, _package in modules]
        if len(names) != len(set(names)):
            raise Unsupported('package-corpus', '', 'duplicate module declaration')
        packages = {name: path for name, path, package in modules if package}
        if set(packages) != {'dbus', 'gi'} or set(distributions) != {'dbus', 'gi'}:
            raise Unsupported('package-corpus', '', 'dbus and gi declarations are both required')
        for name, initializer in packages.items():
            self.corpus_tree(str(Path(initializer).parent), 'package-corpus:' + name,
                             extension_suffixes=extension_suffixes)
            metadata, distribution, version = distributions[name]
            self.capture(metadata, 'distribution-metadata:' + name)
            fields = self.small_body(metadata).decode('utf-8', errors='strict').splitlines()
            if ([line for line in fields if line.startswith('Name:')] != ['Name: ' + distribution] or
                    [line for line in fields if line.startswith('Version:')] != ['Version: ' + version]):
                raise Unsupported('distribution-metadata', metadata, 'name or version differs')
        for name, path, package in modules:
            self.capture(path, 'explicit-module:' + name, candidate=not package)
            self.regular_row(path)

    def package_portions(self, name, search, initial, allowed_roots, extension_suffixes):
        if name not in {'gi', 'gi.overrides'}:
            raise Unsupported('pkgutil-name', name, 'unreviewed package extension')
        allowed_roots = tuple(absolute(root) for root in allowed_roots)

        def portion(path, reason):
            path = absolute(path)
            if not any(path == root or path.startswith(root + '/') for root in allowed_roots):
                raise Unsupported('pkgutil-destination', path, 'outside declared ordinary roots')
            self.capture(path, reason, allowed_roots=allowed_roots)
            target, observed = self.resolved(path)
            if not any(target == root or target.startswith(root + '/') for root in allowed_roots):
                raise Unsupported('pkgutil-destination', target, 'link leaves declared ordinary roots')
            if observed['kind'] == 'directory':
                self.corpus_tree(path, reason, extension_suffixes=extension_suffixes, allowed_roots=allowed_roots)
            elif observed['kind'] != 'absent':
                raise Unsupported('pkgutil-portion', path, 'portion is not a directory')
            return path

        result = [portion(path, 'initial-portion:' + name) for path in initial]
        final_name = name.rsplit('.', 1)[-1]
        for root in search:
            self.capture(root, 'pkgutil-search:' + name, allowed_roots=allowed_roots)
            _target, observed = self.resolved(root)
            if observed['kind'] == 'absent':
                continue
            if observed['kind'] != 'directory':
                raise Unsupported('pkgutil-finder', root, 'only ordinary directory finders are supported')
            candidate = str(Path(root) / final_name)
            self.capture(candidate, 'namespace-candidate:' + name, allowed_roots=allowed_roots)
            _target, found = self.resolved(candidate)
            if found['kind'] == 'directory':
                for suffix in ('.py', '.pyc', *extension_suffixes):
                    shadow = str(Path(root) / (final_name + suffix))
                    self.capture(shadow, 'pkgutil-shadow:' + name, allowed_roots=allowed_roots)
                    if self.resolved(shadow)[1]['kind'] != 'absent':
                        raise Unsupported('pkgutil-shadow', shadow, 'finder precedence needs source review')
                value = portion(candidate, 'namespace-portion:' + name)
                if value not in result:
                    result.append(value)
            elif found['kind'] != 'absent':
                raise Unsupported('pkgutil-portion', candidate, 'named portion is not a directory')
            pkgfile = str(Path(root) / (name + '.pkg'))
            self.capture(pkgfile, 'pkgutil-data:' + name, allowed_roots=allowed_roots)
            if self.resolved(pkgfile)[1]['kind'] == 'absent':
                continue
            text = self.small_body(pkgfile).decode('utf-8', errors='strict')
            for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
                if line and not line.startswith('#'):
                    self.charge(1)
                    result.append(portion(line, 'pkgutil-line:' + pkgfile))
        return result

    def pkgutil_corpus(self, source, digest, search, gi_initial, allowed_roots, extension_suffixes):
        for key in ('GI_TYPELIB_PATH', 'PYGI_OVERRIDES_PATH'):
            if key in os.environ:
                raise Unsupported('package-environment', key, 'required environment absence differs')
        self.capture(source, 'pkgutil-policy-source')
        if self.regular_row(source)['raw']['sha256'] != digest:
            raise Unsupported('pkgutil-source', source, 'reviewed implementation digest differs')
        gi = self.package_portions('gi', search, gi_initial, allowed_roots, extension_suffixes)
        overrides = self.package_portions('gi.overrides', gi, (), allowed_roots, extension_suffixes)
        return {'gi': gi, 'gi.overrides': overrides,
                'policy_source': source, 'policy_sha256': digest,
                'environment_absences': ['GI_TYPELIB_PATH', 'PYGI_OVERRIDES_PATH'],
                'status': 'declared-directory-portions-only', 'authorities': AUTHORITIES}

    def required_family(self, family, paths):
        if not paths:
            raise Unsupported(family, '', 'required family has no grounded declarations')
        for path in paths:
            self.capture(path, 'required-family:' + family)
            if self.resolved(path)[1]['kind'] == 'absent':
                raise Unsupported(family, path, 'required family member is absent')

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
               'group_closed': False, 'reaped': False, 'returncode': None, 'streams': {},
               'error': None, 'cleanup_errors': []}
        self.runs.append(run)
        number = len(self.runs)
        self.document(f'tools/{number:04d}.intent.json', run)
        streams = {}
        selector = selectors.DefaultSelector()
        child = None
        error = None
        finalizing = False
        failed_streams = set()
        selector_failed = False
        started = time.monotonic()

        def cleanup(action, operation, *args):
            try:
                return operation(*args)
            except BaseException as failure:
                run['cleanup_errors'].append(f'{action}: {type(failure).__name__}: {failure}')

        def parent_signal(signum, frame):
            nonlocal error
            if finalizing or error is not None:
                if error is None:
                    error = Incomplete('parent interrupted')
                    run['error'] = str(error)
                run['cleanup_errors'].append('parent SIGTERM during cleanup')
                return
            interrupted(signum, frame)

        def child_limits():
            resource.setrlimit(resource.RLIMIT_CPU, (min(4, remaining), min(5, remaining)))
            resource.setrlimit(resource.RLIMIT_AS, (536870912, 536870912))
            resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_BYTES, FILE_BYTES))
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))

        def drain(wait, cleanup=False):
            for key, _mask in selector.select(wait):
                name = key.data
                if name in failed_streams:
                    continue
                raw = run['streams'][name]
                cap = 2097152 if name == 'stdout' else 262144
                available = max(0, min(cap - raw['size'], 33554432 - self.tool_bytes,
                                       self.total_bytes - self.payload_bytes))
                try:
                    try:
                        chunk = os.read(key.fileobj.fileno(), min(65536, available + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    kept = chunk[:available]
                    stream, digest = streams[name]
                    stream.write(kept)
                    digest.update(kept)
                    raw['size'] += len(kept)
                    self.tool_bytes += len(kept)
                    self.payload_bytes += len(kept)
                    raw['partial_sha256'] = digest.hexdigest()
                    if len(kept) != len(chunk):
                        if not cleanup:
                            raise Incomplete('metadata output cap')
                        run['cleanup_output_truncated'] = True
                        selector.unregister(key.fileobj)
                except BaseException as failure:
                    if not cleanup:
                        raise
                    run['cleanup_errors'].append(f'{name} drain: {type(failure).__name__}: {failure}')
                    failed_streams.add(name)
                    try:
                        selector.unregister(key.fileobj)
                    except BaseException as unregister_error:
                        run['cleanup_errors'].append(f'{name} unregister: {unregister_error}')

        previous_handler = signal.signal(signal.SIGTERM, parent_signal)
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
            for name, pipe in (('stdout', child.stdout), ('stderr', child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            self.document(f'tools/{number:04d}.spawn.json', run)
            deadline = min(started + 5, self.deadline - 3)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise Incomplete('metadata deadline')
                drain(min(0.05, max(0, deadline - time.monotonic())))
            while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= deadline:
                    raise Incomplete('metadata exit deadline')
                time.sleep(0.01)
        except BaseException as failure:
            error = failure
            run['error'] = str(error)
        finally:
            finalizing = True

            def cleanup_drain(wait):
                nonlocal selector_failed
                if selector_failed:
                    time.sleep(wait)
                    return
                try:
                    drain(wait, cleanup=True)
                except BaseException as failure:
                    selector_failed = True
                    run['cleanup_errors'].append(f'selector drain: {type(failure).__name__}: {failure}')

            def signal_group(signum):
                try:
                    os.killpg(child.pid, signum)
                except ProcessLookupError:
                    if signum == 0:
                        run['group_closed'] = True

            if child is not None:
                cleanup_end = min(time.monotonic() + 3, self.deadline)
                cleanup('owned TERM', signal_group, signal.SIGTERM)
                if error is not None:
                    grace = min(time.monotonic() + 1, cleanup_end)
                    while time.monotonic() < grace:
                        cleanup_drain(min(0.02, max(0, grace - time.monotonic())))
                cleanup('owned KILL', signal_group, signal.SIGKILL)
                while time.monotonic() < cleanup_end:
                    waited = cleanup('wait4', os.wait4, child.pid, os.WNOHANG)
                    if waited is None:
                        break
                    pid, status, usage = waited
                    if pid == child.pid:
                        self.child_cpu += usage.ru_utime + usage.ru_stime
                        run['child_cpu_seconds'] = usage.ru_utime + usage.ru_stime
                        child.returncode = os.waitstatus_to_exitcode(status)
                        run.update(reaped=True, returncode=child.returncode)
                        break
                    cleanup_drain(min(0.01, max(0, cleanup_end - time.monotonic())))
                while not selector_failed and selector.get_map() and time.monotonic() < cleanup_end:
                    cleanup_drain(min(0.02, max(0, cleanup_end - time.monotonic())))
                run['pipes_drained'] = (not selector.get_map() and not run['cleanup_errors'] and
                                        not run.get('cleanup_output_truncated', False))
                cleanup('group closure observation', signal_group, 0)
                for pipe in (child.stdout, child.stderr):
                    cleanup('pipe close', pipe.close)
            cleanup('selector close', selector.close)
            for name, (stream, _digest) in streams.items():
                cleanup(f'{name} flush', stream.flush)
                cleanup(f'{name} fsync', lambda: os.fsync(stream.fileno()))
                cleanup(f'{name} close', stream.close)
            run['elapsed_seconds'] = time.monotonic() - started
            cleanup('closure record', self.document, f'tools/{number:04d}.closed.json', run)
            cleanup('restore SIGTERM handler', signal.signal, signal.SIGTERM, previous_handler)
        try:
            self.capture(executable, 'tool-after-exec', eligible=True)
            if self.regular_row(executable)['raw'] != tool:
                raise Incomplete('executed metadata tool changed')
        except BaseException as failure:
            if error is None:
                error = failure
                run['error'] = str(error)
            else:
                run['tool_after_error'] = str(failure)
        if (error is not None or run['cleanup_errors'] or not run.get('pipes_drained') or
                not run['reaped'] or not run['group_closed'] or run['returncode'] != 0):
            raise Incomplete('metadata failed or positive child closure unavailable') from error
        for raw in run['streams'].values():
            raw['sha256'] = raw.pop('partial_sha256')
        try:
            self.document(f'tools/{number:04d}.complete.json', {**run, 'complete': True})
        except BaseException as failure:
            run['error'] = f'completion publication: {type(failure).__name__}: {failure}'
            raise Incomplete('metadata completion publication failed') from failure
        run['complete'] = True
        return run

    def metadata_facts(self, run):
        if (not run.get('complete') or run.get('returncode') != 0 or
                not run.get('reaped') or not run.get('group_closed')):
            raise Incomplete('metadata facts require complete raw output and closure')
        archived = [str(self.output / self.regular_row(path)['raw']['name']) for path in run['subjects']]
        operation = 'readelf' if run['argv'][0] == TOOLS['readelf'] else 'cache'
        expected = ([TOOLS['readelf'], '--wide', '--file-header', '--program-headers', '--dynamic',
                     '--debug-dump=no-follow-links', '--debug-dump=do-not-use-debuginfod', *archived]
                    if operation == 'readelf' else [TOOLS['cache'], '--print-cache', '-C', *archived])
        if run['argv'] != expected or (operation == 'cache' and len(archived) != 1):
            raise Incomplete('metadata facts argv differs from fixed command')
        bodies = {}
        for name in ('stdout', 'stderr'):
            raw = run['streams'][name]
            cap = 2097152 if name == 'stdout' else 262144
            with (self.output / raw['name']).open('rb') as stream:
                body = stream.read(cap + 1)
            if len(body) != raw['size'] or len(body) > cap or hashlib.sha256(body).hexdigest() != raw['sha256']:
                raise Incomplete('metadata archived output changed')
            bodies[name] = body
        if bodies['stderr']:
            raise Incomplete('metadata diagnostic output refuses grammar')
        facts = (elf_facts(bodies['stdout'], archived) if operation == 'readelf' else
                 cache_facts(bodies['stdout'], archived[0]))
        return {'scope': 'authored-text-grammar-only', 'facts': facts, 'selection': 'unobserved',
                'tool_output_qualified': False, 'bootstrap_closed': False, 'authorities': AUTHORITIES}

    def document_paths(self, profile_path, manifest_path):
        documents = {absolute(profile_path), absolute(manifest_path)}
        if len(documents) != 2:
            raise Incomplete('self-referential document aliases')
        identities = set()
        for path in documents:
            current = path
            while True:
                if self.paths[current]['kind'] == 'symlink':
                    raise Incomplete('self-referential document aliases or linked ancestors')
                if current == '/':
                    break
                current = str(Path(current).parent)
            row = self.regular_row(path)
            node = (row['before']['st_dev'], row['before']['st_ino'])
            if node in identities:
                raise Incomplete('self-referential document aliases')
            identities.add(node)
        for path, row in self.paths.items():
            if row.get('complete') and row['kind'] in ('regular', 'symlink'):
                target = self.resolved(path)[1]
                if target['kind'] == 'regular' and path not in documents and (
                        target['before']['st_dev'], target['before']['st_ino']) in identities:
                    raise Incomplete('self-referential document alias membership')
        return documents

    def proposed_profile(self, template, profile_path, manifest_path):
        disabled(template)
        documents = self.document_paths(profile_path, manifest_path)
        profile = json.loads(consumer_json(template))
        profile['files'] = {}
        profile['membership'] = {}
        profile['required_absences'] = []
        for path, row in sorted(self.paths.items()):
            if not row['complete']:
                raise Incomplete('proposed profile contains incomplete input')
            if path in documents:
                continue
            _target, observed = self.resolved(path)
            if observed['kind'] == 'regular':
                profile['files'][path] = observed['raw']['sha256']
            elif observed['kind'] == 'directory':
                profile['membership'][path] = observed['names']
            elif observed['kind'] == 'absent':
                profile['required_absences'].append(path)
        profile['status'] = 'source-unproved'
        profile['unproved'] = list(GAPS)
        serialized_size(profile, JSON_BYTES)
        return profile

    def serialized_projection(self, profile, source_paths, profile_path, manifest_path,
                              loaded_sources, modules, suite_summary, suite_text_bytes, declarations):
        disabled(profile)
        if (not isinstance(declarations, dict) or
                set(declarations) != {'loaded_sources_complete', 'module_report_complete', 'suite_output_bound_declared'} or
                any(value is not True for value in declarations.values())):
            raise Incomplete('explicit supplied projection completeness declarations required')
        profile_path, manifest_path = absolute(profile_path), absolute(manifest_path)
        documents = self.document_paths(profile_path, manifest_path)
        if (documents & (set(profile['files']) | set(source_paths)) or
                len(set(source_paths)) != len(source_paths)):
            raise Incomplete('self-referential documents or duplicate manifest rows')
        if len(set(loaded_sources)) != len(loaded_sources):
            raise Incomplete('duplicate loaded source declarations')
        serialized_size(modules, JSON_BYTES)
        profile_size = serialized_size(profile, JSON_BYTES)
        profile_body = consumer_json(profile)
        if any(path.splitlines() != [path] for path in source_paths):
            raise Incomplete('source manifest path contains a line separator')
        manifest_body = ''.join(self.regular_row(path)['raw']['sha256'] + '  ' + path + '\n'
                                for path in source_paths).encode('utf-8')
        if len(manifest_body) > JSON_BYTES:
            raise Incomplete('proposed manifest serialization cap')
        buffers = {profile_path: profile_body, manifest_path: manifest_body}
        paths = set(profile['files']) | set(source_paths) | documents
        sizes = {path: len(buffers[path]) if path in buffers else self.regular_row(path)['raw']['size']
                 for path in paths}
        for path, digest in profile['files'].items():
            if self.regular_row(path)['raw']['sha256'] != digest:
                raise Incomplete('projection profile digest differs from archived input')
        snapshot = {'files': {}, 'links': {}, 'membership': {}, 'absences': {}}
        for path in sorted(paths):
            row = self.regular_row(path)
            before = row['before']
            digest = hashlib.sha256(buffers[path]).hexdigest() if path in buffers else row['raw']['sha256']
            snapshot['files'][path] = {'sha256': digest, 'size': sizes[path],
                'mode': before['st_mode'], 'uid': before['st_uid'], 'gid': before['st_gid'],
                'device': before['st_dev'], 'inode': before['st_ino'], 'mtime_ns': before['st_mtime_ns']}
        for path, names in profile['membership'].items():
            _target, row = self.resolved(path)
            if row['kind'] != 'directory' or row['names'] != names:
                raise Incomplete('projection directory membership differs')
            snapshot['membership'][path] = names
        for path in profile['required_absences']:
            if self.resolved(path)[1]['kind'] != 'absent':
                raise Incomplete('projection required absence differs')
            snapshot['absences'][path] = True
        pending = list(paths) + list(profile['membership']) + [
            str(Path(path).parent) for path in profile['required_absences']]
        seen = set()
        while pending:
            path = pending.pop()
            if path in seen:
                continue
            seen.add(path)
            row = self.paths[path]
            if row['kind'] == 'symlink':
                before = row['before']
                snapshot['links'][path] = {'target': row['target'], 'mode': before['st_mode'],
                    'uid': before['st_uid'], 'gid': before['st_gid'], 'device': before['st_dev'],
                    'inode': before['st_ino'], 'mtime_ns': before['st_mtime_ns']}
                pending.append(row['target_path'])
            if path != '/':
                pending.append(str(Path(path).parent))
        snapshot_size = serialized_size(snapshot, JSON_BYTES)
        sources = {}
        source_hex = 0
        extension_reads = 0
        for name, module in modules.items():
            if not isinstance(name, str) or not isinstance(module, dict):
                raise Incomplete('invalid supplied module report')
            origin = module.get('origin')
            if isinstance(origin, str) and origin.endswith('.so'):
                if origin not in paths:
                    raise Incomplete('module extension lacks declared buffer')
                raw = self.regular_row(origin)['raw']
                if module.get('size') != raw['size'] or module.get('sha256') != raw['sha256']:
                    raise Incomplete('module extension report differs from archived buffer')
                extension_reads += raw['size']
        for path in loaded_sources:
            if path not in paths or not path.endswith('.py'):
                raise Incomplete('loaded source lacks declared Python buffer')
            body = self.small_body(path)
            source_hex += 2 * len(body)
            sources[path] = {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'raw': body.hex()}
        checked = {path: {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'raw': body.hex()}
                   for path, body in buffers.items()}
        report = {'kind': 'import-only', 'application_enabled': profile['application_enabled'],
                  'search': profile['stdlib_search'], 'modules': modules,
                  'source_buffers': sources, 'checked_documents': checked}
        report_size = serialized_size(report, 25165824)
        summary_size = serialized_size(suite_summary, 33554432) + 1
        if not isinstance(suite_text_bytes, int) or isinstance(suite_text_bytes, bool) or suite_text_bytes < 0:
            raise Incomplete('suite text requires a nonnegative declared byte count')
        loop = sum(sizes[path] for path in profile['files']) + sum(sizes[path] for path in source_paths)
        union = sum(sizes.values())
        archived_sizes = {path: self.regular_row(path)['raw']['size'] for path in paths}
        archived_documents = sum(archived_sizes[path] for path in documents)
        archived_union = sum(archived_sizes.values())
        archived_largest = max(archived_sizes.values(), default=0)
        largest = max(sizes.values(), default=0)
        membership = max(map(len, profile['membership'].values()), default=0)
        current = {'entry_loop': limit_charge(loop, 536870912),
                   'offline_union': limit_charge(union, 536870912),
                   'two_snapshot_payload': limit_charge(2 * union, TOTAL_BYTES),
                   'regular_file': limit_charge(largest, 134217728),
                   'union_paths': limit_charge(len(paths), 4096),
                   'membership': limit_charge(membership, 4096),
                   'profile': limit_charge(profile_size, 1048576),
                   'manifest': limit_charge(len(manifest_body), 1048576),
                   'snapshot_map': limit_charge(snapshot_size, 1048576),
                   'import_report': limit_charge(report_size, 1048576),
                   'suite_file': limit_charge(max(snapshot_size, min(largest, 4194304)), 4194304)}
        proposed = {'entry_loop': limit_charge(loop, TOTAL_BYTES),
                    'offline_union': limit_charge(union, TOTAL_BYTES),
                    'two_snapshot_payload': limit_charge(2 * union, TOTAL_BYTES),
                    'regular_file': limit_charge(largest, FILE_BYTES),
                    'union_paths': limit_charge(len(paths), RECORDS),
                    'membership': limit_charge(membership, RECORDS),
                    'profile': limit_charge(profile_size, JSON_BYTES),
                    'manifest': limit_charge(len(manifest_body), JSON_BYTES),
                    'snapshot_map': limit_charge(snapshot_size, JSON_BYTES),
                    'import_report': limit_charge(report_size, 25165824),
                    'suite_output': limit_charge(report_size + 1 + summary_size + suite_text_bytes, 33554432)}
        archived_fits = (archived_largest <= 134217728 and archived_documents <= 2097152 and
                         all(archived_sizes[path] <= 1048576 for path in documents) and
                         membership <= 4096)
        return {'status': 'incomplete', 'selection': 'unobserved', 'authorities': AUTHORITIES,
                'basis': 'exact serialization of supplied declarations and archived buffers; no runtime module observation',
                'declarations': declarations,
                'profile': profile, 'manifest_hex': manifest_body.hex(), 'snapshot': snapshot,
                'current': current, 'proposed': proposed,
                'entry': {'loop_bytes': loop, 'document_bytes': profile_size + len(manifest_body),
                          'total_read_bytes': loop + profile_size + len(manifest_body),
                          'loaded_source_read_bytes': source_hex // 2, 'extension_report_read_bytes': extension_reads,
                          'all_declared_read_bytes': loop + profile_size + len(manifest_body) + source_hex // 2 + extension_reads},
                'archived': {'entry': {'loop_bytes': loop, 'total_read_bytes': loop + archived_documents,
                                      'fits_current_limits': None if archived_fits and loop <= 536870912 else False},
                             'offline': {'union_bytes': archived_union,
                                         'fits_current_limits': None if archived_fits and archived_union <= 536870912 and len(paths) <= 4096 else False},
                             'import_report': {'document_hex_bytes': 2 * archived_documents,
                                               'full_serialized_bytes': None}},
                'offline': {'union_bytes': union, 'union_paths': len(paths),
                            'two_snapshot_payload_bytes': 2 * union,
                            'two_snapshot_map_bytes': 2 * snapshot_size},
                'import_report': {'document_hex_bytes': 2 * (profile_size + len(manifest_body)),
                                  'source_buffer_hex_bytes': source_hex, 'full_serialized_bytes': report_size,
                                  'stdout_bytes': report_size + 1},
                'proposed_profile_serialized_bytes': profile_size,
                'snapshot_map_serialized_bytes': snapshot_size,
                'producer_output_bytes': report_size + 1 + summary_size + suite_text_bytes,
                'producers': {'import_stdout_bytes': report_size + 1,
                              'suite_stdout_bytes': summary_size, 'suite_stderr_bytes': suite_text_bytes,
                              'combined_output_is_proposed_aggregate': True},
                'acquisition_payload_bytes': self.payload_bytes, 'tool_output_bytes': self.tool_bytes,
                'remaining_gates': ['complete actor and tool bootstrap closure', 'actual module and suite text bounds',
                                    'generated document metadata is hypothetical at archived document identities',
                                    'matching consumer source changes and separately granted proof']}

    def projection_documents(self, projection, final_record):
        authorities = final_record.get('authorities')
        if (final_record.get('status') != 'incomplete' or
                not isinstance(authorities, dict) or set(authorities) != set(AUTHORITIES) or
                any(value is not False for value in authorities.values()) or
                final_record.get('selection') != 'unobserved'):
            raise Incomplete('projection final record cannot grant acquisition authority')
        documents = {'census.json': {'status': 'incomplete', 'paths': self.paths,
                                    'authorities': AUTHORITIES, 'selection': 'unobserved'},
                     'budget-projection.json': projection, 'projection-final.json': final_record}
        charges = {name: producer_size(value) for name, value in documents.items()}
        total = self.json_bytes + sum(charges.values())
        return documents, {'already_written_bytes': self.json_bytes, 'records': charges,
                           'combined': limit_charge(total, JSON_BYTES)}

    def publish_projection(self, projection, final_record):
        documents, charge = self.projection_documents(projection, final_record)
        if not charge['combined']['fits']:
            raise Incomplete('combined acquisition JSON cap')
        for name, value in documents.items():
            self.document(name, value)
        return charge

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
