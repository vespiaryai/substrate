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
import resource
import signal
import stat
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
OUTPUT = Path('/home/zack/.codex/orchestrate/vespiary-goal330/reviews/native-loading-input-profile-preparation/census-first')
SEARCH = ['/usr/lib64/python314.zip', '/usr/lib64/python3.14', '/usr/lib64/python3.14/lib-dynload']
PACKAGE = Path('/usr/lib64/python3.14/site-packages')
MAX_FILE = 268435456
MAX_TOTAL = 1073741824
MAX_ENTRIES = 25000
MAX_JSON = 8388608
START = time.monotonic()
records = {}
elf = {}
actors = set()
total = 0
archive = None
generated = 0


def check():
    if time.monotonic() - START > 120:
        raise TimeoutError('120-second data acquisition ceiling')
    if len(records) >= MAX_ENTRIES:
        raise RuntimeError('25000-entry data census ceiling')


def metadata(info):
    return {key: getattr(info, 'st_' + key) for key in (
        'mode', 'uid', 'gid', 'dev', 'ino', 'size', 'mtime_ns', 'ctime_ns')}


def permitted(path):
    name = str(path)
    return name.startswith(('/usr/', '/lib/', '/lib64/', str(ROOT) + '/')) or name in (
        '/etc', '/lib', '/lib64', '/usr', '/') or name.startswith((
        '/etc/ld.so.', '/etc/pki/tls/openssl', '/etc/ssl/openssl', '/etc/crypto-policies/')) or name in (
        '/etc/nsswitch.conf', '/etc/passwd', '/etc/group', '/etc/hosts', '/etc/resolv.conf',
        '/etc/host.conf', '/etc/gai.conf', '/etc/locale.conf', '/etc/localtime',
        '/etc/authselect/nsswitch.conf', '/run/systemd/resolve/stub-resolv.conf', '/etc/mdns.allow')


def capture(path, recurse=False, actor=False):
    global total
    path = Path(os.path.abspath(path))
    check()
    if not permitted(path):
        raise RuntimeError('unreviewed data pathname: ' + str(path))
    name = str(path)
    known_actor = name in actors
    if actor:
        actors.add(name)
    if name in records:
        if actor and not known_actor and not records[name].get('absent') and name not in elf:
            if 'link' in records[name]:
                capture(path.parent / records[name]['link'], actor=True)
            elif 'offset' in records[name]:
                body = raw(path)
                if body.startswith(b'\x7fELF'):
                    elf[name] = dynamic(body)
        return
    try:
        info = path.lstat()
    except FileNotFoundError:
        records[name] = {'absent': True}
        return
    row = metadata(info)
    records[name] = row
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        if len(os.fsencode(target)) > 4096:
            raise RuntimeError('symlink target ceiling')
        row['link'] = target
        capture(path.parent / target, recurse, actor)
    elif stat.S_ISDIR(info.st_mode):
        children = []
        with os.scandir(path) as entries:
            for entry in entries:
                check()
                if len(children) >= MAX_ENTRIES:
                    raise RuntimeError('directory membership ceiling')
                children.append(entry.name)
        row['children'] = sorted(children)
        if recurse:
            for child in row['children']:
                if child != 'site-packages':
                    capture(path / child, True)
    elif stat.S_ISREG(info.st_mode):
        limit = min(MAX_FILE, MAX_TOTAL - total)
        if info.st_size > limit:
            raise RuntimeError('single-file or remaining aggregate byte ceiling: ' + name)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if metadata(opened) != metadata(info):
                raise RuntimeError('input changed before capture: ' + name)
            body = stream.read(limit + 1)
            if len(body) != info.st_size or metadata(os.fstat(stream.fileno())) != metadata(info):
                raise RuntimeError('input changed during capture: ' + name)
        if len(body) > limit:
            raise RuntimeError('input grew beyond remaining byte ceiling')
        row.update(offset=archive.tell(), sha256=hashlib.sha256(body).hexdigest())
        archive.write(body)
        archive.flush()
        total += len(body)
        if actor and body.startswith(b'\x7fELF'):
            elf[name] = dynamic(body)
    else:
        raise RuntimeError('nonregular input: ' + name)


def dynamic(body):
    if body[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', body, 18)[0] != 62:
        raise RuntimeError('actor is not installed ELF64 little-endian x86-64')
    offset = struct.unpack_from('<Q', body, 32)[0]
    size, count = struct.unpack_from('<HH', body, 54)
    if count > 4096 or size != 56 or offset + size * count > len(body):
        raise RuntimeError('ELF program header ceiling or extent')
    segments = [struct.unpack_from('<IIQQQQQQ', body, offset + i * size) for i in range(count)]
    tags = []
    interpreter = None
    for kind, flags, pos, address, physical, filesz, memsz, align in segments:
        if pos + filesz > len(body):
            raise RuntimeError('ELF segment extent')
        if kind == 3:
            interpreter = body[pos:pos + filesz].rstrip(b'\0').decode()
        if kind == 2:
            if filesz > 1048576 or filesz % 16:
                raise RuntimeError('ELF dynamic extent')
            for index in range(pos, pos + filesz, 16):
                tag, value = struct.unpack_from('<qQ', body, index)
                if tag == 0:
                    break
                tags.append((tag, value))
    address = next((value for tag, value in tags if tag == 5), None)
    if address is None:
        return {'needed': [], 'rpath': [], 'runpath': [], 'interpreter': interpreter}
    base = next(pos + address - virtual for kind, flags, pos, virtual, physical, filesz, memsz, align
                in segments if kind == 1 and virtual <= address < virtual + filesz)
    def string(index):
        end = body.index(b'\0', base + index, min(len(body), base + index + 4096))
        return body[base + index:end].decode()
    return {'needed': [string(value) for tag, value in tags if tag == 1],
            'rpath': [string(value) for tag, value in tags if tag == 15],
            'runpath': [string(value) for tag, value in tags if tag == 29], 'interpreter': interpreter}


def raw(path):
    row = records[str(path)]
    if row.get('link'):
        return raw(Path(os.path.abspath(Path(path).parent / row['link'])))
    with (OUTPUT / 'inputs.raw').open('rb') as stream:
        stream.seek(row['offset'])
        return stream.read(row['size'])


def cache_entries():
    body = raw(Path('/etc/ld.so.cache'))
    if body[:20] != b'glibc-ld.so.cache1.1':
        raise RuntimeError('unreviewed loader cache format')
    count = struct.unpack_from('<I', body, 20)[0]
    if count > MAX_ENTRIES or 48 + count * 24 > len(body):
        raise RuntimeError('loader cache entry ceiling')
    result = {}
    for index in range(count):
        flags, key, value, osv, hwcap = struct.unpack_from('<IIIIQ', body, 48 + index * 24)
        def string(offset):
            end = body.index(b'\0', offset, min(len(body), offset + 4096))
            return body[offset:end].decode()
        result.setdefault(string(key), []).append({'path': string(value), 'flags': flags, 'hwcap': hwcap})
    return result


def write_json(name, value):
    global generated
    limit = MAX_JSON - generated - (0 if name == 'failure.json' else 4096)
    body = bytearray()
    for piece in json.JSONEncoder(sort_keys=True, indent=2).iterencode(value):
        chunk = piece.encode()
        if len(body) + len(chunk) + 1 > limit:
            raise RuntimeError('aggregate generated JSON ceiling')
        body.extend(chunk)
    body.extend(b'\n')
    generated += len(body)
    with (OUTPUT / name).open('xb') as stream:
        stream.write(body)


def acquire():
    for root in SEARCH:
        capture(root, True)
    for package in ('dbus', 'gi', 'dbus_python-1.4.0-py3.14.egg-info', 'PyGObject-3.56.3.dist-info'):
        capture(PACKAGE / package, True)
    capture(PACKAGE)
    for root in SEARCH:
        if root.endswith('.zip'):
            continue
        for suffix in ('gi', 'gi.pkg', 'dbus', 'dbus.pkg'):
            capture(Path(root) / suffix, True)
    for path in ('/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ld.so.conf.d', '/etc/ld.so.preload',
                 '/usr/lib/locale/locale-archive', '/usr/lib/locale/C.utf8', '/etc/locale.conf',
                 '/etc/localtime', '/etc/nsswitch.conf', '/etc/passwd', '/etc/group', '/etc/hosts',
                 '/etc/resolv.conf', '/etc/host.conf', '/etc/gai.conf', '/etc/mdns.allow', '/etc/ssl/openssl.cnf',
                 '/etc/pki/tls/openssl.cnf', '/etc/pki/tls/openssl.d',
                 '/etc/crypto-policies/back-ends/opensslcnf.config', '/usr/lib64/ossl-modules',
                 '/usr/lib64/girepository-1.0', '/usr/lib/girepository-1.0',
                 '/usr/share/girepository-1.0'):
        capture(path, path in ('/etc/ld.so.conf.d', '/etc/pki/tls/openssl.d', '/usr/lib/locale/C.utf8'))
    for namespace in ('GLib-2.0', 'GObject-2.0', 'Gio-2.0', 'GModule-2.0'):
        capture('/usr/lib64/girepository-1.0/' + namespace + '.typelib')
    sources = ROOT / 'hack/goal330-verify-runtime'
    for name in ('native_python_entry', 'native_offline_entry', 'native_api_observer', 'native_client_entry',
                 'native_holder_fixture', 'systemd_job', 'test_native_api_observer', 'test_systemd_job'):
        capture(sources / (name + '.py'))
    capture(ROOT / 'docs/dev/verify-runtime-20261020/native-python-profile.json')
    capture(ROOT / 'docs/dev/verify-runtime-20261020/native-api-inputs.sha256')
    manifest = ROOT / 'docs/dev/verify-runtime-20261020/native-api-inputs.sha256'
    for line in raw(manifest).decode().splitlines():
        digest, name = line.split('  ', 1)
        capture(Path(name) if name.startswith('/') else ROOT / name)
    capture(Path(__file__))
    for tool in ('python3', 'env', 'timeout', 'printf', 'bash'):
        capture('/usr/bin/' + tool, actor=True)
    for name in ('_dbus_bindings', '_dbus_glib_bindings', 'gi/_gi'):
        capture(PACKAGE / (name + '.cpython-314-x86_64-linux-gnu.so'), actor=True)
    extensions = ('_hashlib', '_blake2', '_json', '_struct', '_posixsubprocess', 'select', 'math',
                  '_random', '_sha2', '_bisect', '_socket', '_heapq', '_pickle', '_opcode',
                  'fcntl', 'resource', 'array', 'pyexpat', '_ssl', '_datetime', 'binascii',
                  '_contextvars', 'zlib')
    for name in extensions:
        path = Path(SEARCH[2]) / (name + '.cpython-314-x86_64-linux-gnu.so')
        capture(path, actor=True)
    for name in ('glib-2.0', 'gobject-2.0', 'gio-2.0', 'gmodule-2.0', 'nss_systemd', 'nss_myhostname',
                 'nss_mdns4_minimal', 'nss_resolve', 'nss_dns', 'nss_files'):
        soname = 'lib' + name + ('.so.2' if name.startswith('nss_') else '.so.0')
        capture('/usr/lib64/' + soname, actor=True)
    cache = cache_entries()
    search = ['/usr/lib64', '/lib64', '/usr/lib64/pipewire-0.3/jack']
    for directory in search:
        capture(directory)
        for suffix in ('glibc-hwcaps', 'glibc-hwcaps/x86-64-v2', 'glibc-hwcaps/x86-64-v3', 'glibc-hwcaps/x86-64-v4'):
            capture(Path(directory) / suffix)
    processed = set()
    while set(elf) - processed:
        for name in sorted(set(elf) - processed):
            check()
            processed.add(name)
            row = elf[name]
            if row['interpreter']:
                capture(row['interpreter'], actor=True)
            directories = list(search)
            for text in row['rpath'] + row['runpath']:
                for directory in text.split(':'):
                    directory = directory.replace('${ORIGIN}', str(Path(name).parent)).replace('$ORIGIN', str(Path(name).parent))
                    if '$' in directory or not directory.startswith('/'):
                        raise RuntimeError('unreviewed ELF path expansion')
                    capture(directory)
                    directories.append(directory)
            row['candidates'] = {}
            for needed in row['needed']:
                if '/' in needed:
                    raise RuntimeError('unreviewed DT_NEEDED pathname')
                candidates = {str(Path(directory) / needed) for directory in directories}
                candidates.update(item['path'] for item in cache.get(needed, []) if item['flags'] == 0x303)
                row['candidates'][needed] = sorted(candidates)
                for candidate in sorted(candidates):
                    capture(candidate, actor=True)
                if not any(not records[candidate].get('absent') for candidate in candidates):
                    raise RuntimeError('unresolved ELF dependency: ' + needed)
    for name in list(records):
        for parent in Path(name).parents:
            if permitted(parent):
                capture(parent)
    return cache


def main():
    global archive
    if sys.argv[1:] != ['prepare-native-loading-inputs'] or list(sys.path) != SEARCH:
        raise RuntimeError('fixed data operation and isolated search required')
    if not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode:
        raise RuntimeError('isolated no-site no-write-bytecode flags required')
    resource.setrlimit(resource.RLIMIT_CPU, (120, 122))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TOTAL, MAX_TOTAL))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('120-second wall ceiling')))
    signal.alarm(120)
    OUTPUT.mkdir(mode=0o700)
    write_json('intent.json', {'argv': sys.argv, 'environment': dict(os.environ), 'search': list(sys.path),
                             'limits': {'file': MAX_FILE, 'aggregate': MAX_TOTAL, 'entries': MAX_ENTRIES, 'json': MAX_JSON}})
    try:
        with (OUTPUT / 'inputs.raw').open('xb') as archive:
            cache = acquire()
        regular = {name: row['sha256'] for name, row in records.items() if 'sha256' in row}
        membership = {name: row['children'] for name, row in records.items() if 'children' in row}
        proposed = json.loads(raw(ROOT / 'docs/dev/verify-runtime-20261020/native-python-profile.json'))
        proposed.update(files=regular, membership=membership, required_absences=sorted(
            name for name, row in records.items() if row.get('absent')))
        profile_bytes = len(json.dumps(proposed, sort_keys=True, indent=2).encode())
        projection = {'single_file_bytes': max(row['size'] for row in records.values() if 'sha256' in row),
                      'unique_regular_bytes': sum(row['size'] for row in records.values() if 'sha256' in row),
                      'regular_count': len(regular), 'membership_max': max(map(len, membership.values()), default=0),
                      'proposed_profile_bytes': profile_bytes,
                      'import_report_profile_hex_bytes_alone': profile_bytes * 2,
                      'complete': False}
        write_json('census.json', {'budget_projection': projection, 'records': records, 'actor_candidates': sorted(actors), 'elf': elf,
                                 'loader_cache': cache, 'bytes': total, 'entries': len(records),
                                 'runtime_selection_observed': False, 'complete': False})
        write_json('result.json', {'status': 'data-captured-unreviewed', 'elapsed': time.monotonic() - START,
                                  'bytes': total, 'entries': len(records), 'complete': False})
    except BaseException as error:
        write_json('failure.json', {'error': repr(error), 'elapsed': time.monotonic() - START,
                                   'bytes': total, 'entries': len(records), 'complete': False})
        raise


if __name__ == '__main__':
    main()
