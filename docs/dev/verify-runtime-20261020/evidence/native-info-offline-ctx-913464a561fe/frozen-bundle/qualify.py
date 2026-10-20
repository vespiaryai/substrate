import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time

REPO = Path('/home/zack/orca/workspaces/substrate-goal330-20261020/goal330-daemon-only-bootstrap')
DRIVER = Path(__file__).resolve()
BUNDLE = DRIVER.parent
OUT = Path('/tmp/goal330-daemon-native-info-offline-ctx-913464a561fe')
UNIT = 'goal330-daemon-native-info-offline-ctx-913464a561fe.service'
LOCK = Path('/tmp/vespiary-heavy-validation.lock')
GUARD = Path('/home/zack/orca/workspaces/vespiary-continuation/goal330-postgres-close-baseline/docs/wayfinder/effect-evidence/postgres-close-baseline-20261020/source-guard.py')
FIXTURE = 'hack/goal330-verify-runtime/native-info-offline-ctx-913464a561fe/guard-refusal.txt'
MANIFESTS = [BUNDLE / "source.sha256", *[REPO / 'docs/dev/verify-runtime-20261020' / name for name in
             ('daemon-native-info-output.sha256', 'daemon-only-native.sha256', 'daemon-only-mock-native.sha256')]]
ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/home/zack', 'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(OUT / 'tmp')}


def save(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def call(name, argv, seconds=3, env=None):
    with (OUT / (name + '.stdout')).open('xb') as stdout, (OUT / (name + '.stderr')).open('xb') as stderr:
        try:
            result = subprocess.run(argv, cwd=REPO, env=env, close_fds=True,
                                    stdout=stdout, stderr=stderr, timeout=seconds)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    save(name + '.command.json', {'argv': argv, 'exit': code})
    return code, (OUT / (name + '.stdout')).read_text(), (OUT / (name + '.stderr')).read_text()


def identity(pid):
    root = Path('/proc') / str(pid)
    stat = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    group = (root / 'cgroup').read_text().strip()
    assert group.startswith('0::')
    return {'pid': pid, 'start': int(stat[19]), 'group': group[3:]}


def gone(who):
    try:
        return identity(who['pid'])['start'] != who['start']
    except FileNotFoundError:
        return True


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def path_for(group):
    assert group.startswith('/') and '..' not in group.split('/')
    path = Path('/sys/fs/cgroup') / group.lstrip('/')
    assert path.resolve() == path
    return path


def properties(name, text, required):
    rows = [line.split('=', 1) for line in text.splitlines()]
    assert all(len(row) == 2 for row in rows), name
    result = dict(rows)
    assert len(result) == len(rows) and set(result) == set(required), (name, result)
    return result


def closed(phase, group, before=False):
    keys = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'Job', 'Result']
    rc, out, err = call(phase + '-unit', ['/usr/bin/systemctl', '--user', 'show', UNIT,
                                      '--property=' + ','.join(keys)])
    p = properties(phase, out, keys)
    assert not err and (rc == 0 or (rc == 1 and p['LoadState'] == 'not-found'))
    assert p['LoadState'] in ('loaded', 'not-found') and p['ActiveState'] in ('inactive', 'failed')
    assert p['SubState'] in ('dead', 'failed') and p['MainPID'] == '0'
    assert p['ControlGroup'] in ('', group) and p['Job'] == ''
    if before:
        assert p['LoadState'] == 'not-found' and p['ActiveState'] == 'inactive' and p['SubState'] == 'dead'
    rc, out, err = call(phase + '-jobs', ['/usr/bin/systemctl', '--user', 'list-jobs', '--no-pager', '--output=json'])
    assert rc == 0 and not err
    jobs = json.loads(out) if out.strip() else []
    assert isinstance(jobs, list)
    assert all(isinstance(row, dict) and isinstance(row.get('unit'), str) for row in jobs)
    assert not any(row['unit'] == UNIT for row in jobs)
    assert absent(path_for(group))
    return p


def native(phase):
    for index, manifest in enumerate([*MANIFESTS, BUNDLE / 'driver-native.sha256']):
        rc, _, _ = call(phase + '-manifest-' + str(index), ['/usr/bin/sha256sum', '-c', str(manifest)])
        assert rc == 0
    assert hashlib.sha256(GUARD.read_bytes()).hexdigest() == 'f98fc81cd69683177d44492150f68eec36bef531fe496a5bcd5cdc90979a9296'


def inputs():
    names = subprocess.check_output(['/usr/bin/git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=REPO).decode().split('\0')
    return {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
            if (REPO / name).is_file() else None for name in sorted(set(names)) if name}


def source_bytes(phase):
    manifest = BUNDLE / "source.sha256"
    names = [line.split('  ', 1)[1] for line in manifest.read_text().splitlines()]
    assert len(names) == 13 and len(set(names)) == 13
    rows = {}
    for name in names:
        data = (REPO / name).read_bytes()
        destination = OUT / ('source-' + phase) / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(data)
        rows[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    save('source-' + phase + '.json', rows)
    return rows


def lock_held(owner):
    text = Path('/proc/locks').read_text()
    rows = [row.split() for row in text.splitlines()]
    st = LOCK.stat()
    assert [st.st_dev, st.st_ino] == owner['lock']
    key = f'{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}'
    assert any(len(row) >= 6 and row[1:4] == ['FLOCK', 'ADVISORY', 'WRITE']
               and row[4] == str(owner['pid']) and row[5] == key for row in rows)
    return True


def no_lock_fd(owner):
    for entry in Path('/proc/self/fd').iterdir():
        try:
            st = entry.stat()
        except FileNotFoundError:
            continue
        assert [st.st_dev, st.st_ino] != owner['lock']


def unit_body():
    owner = json.loads((OUT / 'owner.json').read_text())
    own = identity(os.getpid())
    expected = (OUT / 'expected-cgroup.txt').read_text().strip()
    assert own['group'] == expected and owner['group'] != expected
    assert identity(owner['pid']) == {k: owner[k] for k in ('pid', 'start', 'group')}
    no_lock_fd(owner)
    lock_held(owner)
    rc, out, err = call('live-unit', ['/usr/bin/systemctl', '--user', 'show', UNIT,
        '--property=InvocationID,MainPID,ControlGroup,Slice,RuntimeMaxUSec,TimeoutStopUSec,KillMode,SendSIGKILL,Restart,RuntimeRandomizedExtraUSec'], env={'PATH': '/usr/bin:/bin', 'HOME': '/home/zack', 'XDG_RUNTIME_DIR': '/run/user/1000'})
    keys = ['InvocationID', 'MainPID', 'ControlGroup', 'Slice', 'RuntimeMaxUSec', 'TimeoutStopUSec', 'KillMode', 'SendSIGKILL', 'Restart', 'RuntimeRandomizedExtraUSec']
    p = properties('live', out, keys)
    assert rc == 0 and not err and len(p['InvocationID']) == 32 and int(p['InvocationID'], 16)
    assert p['MainPID'] == str(own['pid']) and p['ControlGroup'] == expected and p['Slice'] == 'app.slice'
    assert p['RuntimeMaxUSec'] == '1min' and p['TimeoutStopUSec'] == '5s'
    assert p['KillMode'] == 'control-group' and p['SendSIGKILL'] == 'yes' and p['Restart'] == 'no'
    assert p['RuntimeRandomizedExtraUSec'] == '0'
    leaf = path_for(expected)
    controls = {}
    for path in [leaf, *leaf.parents]:
        if path == Path('/sys/fs'):
            break
        controls[str(path)] = {key: (path / key).read_text().strip() for key in
                              ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max') if (path / key).exists()}
    values = controls[str(leaf)]
    quota, period = values['cpu.max'].split()
    assert quota != 'max' and 0 < int(quota) <= 2 * int(period)
    assert values['memory.max'] != 'max' and 0 < int(values['memory.max']) <= 2147483648
    assert values['memory.swap.max'] == '0' and values['pids.max'] != 'max' and 0 < int(values['pids.max']) <= 128
    assert resource.getrlimit(resource.RLIMIT_AS) == (2147483648, 2147483648)
    save('unit-owner.json', own | {'invocation': p['InvocationID'], 'controls': controls, 'lockInherited': False, 'parentLockHeld': True})
    native('unit-before')
    fixture = REPO / FIXTURE
    fixture.parent.mkdir(mode=0o700)
    with fixture.open('xb') as stream:
        stream.write(b'unchanged\n')
    assert FIXTURE in subprocess.check_output(['/usr/bin/git', 'ls-files', '--others', '--exclude-standard'], cwd=REPO).decode().splitlines()
    (OUT / 'fixture-original').write_bytes(fixture.read_bytes())
    for phase, child, expected_exit in [
        ('stable', ['/usr/bin/true'], 0),
        ('mutated', ['/bin/bash', '-euc', 'printf "changed\\n" > "$1"', 'bash', FIXTURE], 97),
        ('restored', ['/usr/bin/true'], 0),
    ]:
        if phase == 'restored':
            fixture.write_bytes((OUT / 'fixture-original').read_bytes())
        native(phase + '-before')
        rc, _, _ = call(phase, ['/usr/bin/python3', '-I', '-B', str(GUARD), str(OUT / phase), *child], 10, ENV)
        receipt = json.loads((OUT / (phase + '.guard.json')).read_text())
        assert rc == expected_exit and receipt['command_exit'] == 0
        assert receipt['stable'] is (phase != 'mutated')
        assert receipt['changed'] == ([FIXTURE] if phase == 'mutated' else [])
        before = json.loads((OUT / (phase + '.before.json')).read_text())
        after = json.loads((OUT / (phase + '.after.json')).read_text())
        assert sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key)) == receipt['changed']
        if phase != 'mutated':
            assert before == after
        native(phase + '-after')
    assert (OUT / 'stable.before.json').read_bytes() == (OUT / 'restored.after.json').read_bytes()
    assert fixture.read_bytes() == b'unchanged\n'
    suite = '/usr/bin/python3 -B -m unittest discover -s hack/goal330-verify-runtime -p test_daemon_bootstrap.py -v\n/usr/bin/python3 -B -m unittest discover -s hack/goal330-verify-runtime -p test_systemd_job.py -v\n'
    rc, out, err = call('suite', ['/usr/bin/python3', '-I', '-B', str(GUARD), str(OUT / 'suite'), '/bin/bash', '-euc', suite], 50, ENV)
    assert rc == 0 and err.count('Ran 24 tests') == 1 and err.count('Ran 4 tests') == 1
    assert err.count('\nOK\n') == 2 and 'skipped' not in err.lower()
    expected_cases = json.loads((BUNDLE / 'expected-case-ids.json').read_text())
    actual_cases = []
    for line in err.splitlines():
        if line.startswith('test_'):
            assert line.endswith(' ... ok'), line
            actual_cases.append(line.split(' (', 1)[1].split(')', 1)[0])
    assert len(actual_cases) == 28 and len(set(actual_cases)) == 28
    assert sorted(actual_cases) == sorted(expected_cases)
    save('actual-case-ids.json', {'count': len(actual_cases), 'ids': actual_cases})
    s = json.loads((OUT / 'suite.guard.json').read_text())
    assert s['command_exit'] == 0 and s['stable'] is True and s['changed'] == []
    assert (OUT / 'suite.before.json').read_bytes() == (OUT / 'suite.after.json').read_bytes()
    guarded = json.loads((OUT / 'suite.before.json').read_text())
    assert all(guarded[name] == value for name, value in json.loads((OUT / 'source-before.json').read_text()).items())
    native('suite-after')
    native('unit-after')
    save('unit-result.json', {'suiteCases': 28, 'suiteExit': 0, 'guardControlExits': [0, 97, 0]})


def owner_body():
    os.umask(0o077)
    OUT.mkdir(mode=0o700)
    (OUT / 'tmp').mkdir(mode=0o700)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    st = os.fstat(fd)
    owner = identity(os.getpid()) | {'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                                   'lock': [st.st_dev, st.st_ino], 'argv': sys.argv}
    save('owner.json', owner)
    end = time.monotonic() + 90
    result = 1
    try:
        native('parent-before')
        source_bytes('before')
        before = inputs()
        save('inputs.before.json', before)
        save('driver.before.json', {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in BUNDLE.iterdir() if p.is_file()})
        rc, out, err = call('slice', ['/usr/bin/systemctl', '--user', 'show', 'app.slice', '--property=ControlGroup'])
        assert rc == 0 and not err
        parent = properties('slice', out, ['ControlGroup'])['ControlGroup']
        assert parent.endswith('/app.slice')
        path_for(parent).lstat()
        group = parent + '/' + UNIT
        (OUT / 'expected-cgroup.txt').write_text(group + '\n')
        assert owner['group'] != group and not owner['group'].startswith(group + '/')
        closed('before', group, True)
        argv = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', '70s', '/usr/bin/systemd-run', '--user', '--wait', '--pipe', '--collect', '--unit=' + UNIT, '--working-directory=' + str(REPO)]
        for prop in ['Slice=app.slice', 'CPUQuota=200%', 'MemoryMax=2G', 'MemorySwapMax=0', 'TasksMax=128', 'RuntimeMaxSec=60', 'RuntimeRandomizedExtraSec=0', 'TimeoutStopSec=5', 'KillMode=control-group', 'SendSIGKILL=yes', 'Restart=no', 'LimitAS=2147483648', 'LimitCPU=50']:
            argv += ['-p', prop]
        argv += ['/usr/bin/env', '-i', *[key + '=' + value for key, value in ENV.items()], '/usr/bin/python3', '-I', '-B', str(DRIVER), 'unit']
        rc, _, _ = call('launch', argv, 73)
        result = int(rc != 0)
    except BaseException as error:
        save('failure.json', {'error': repr(error)})
    try:
        group = (OUT / 'expected-cgroup.txt').read_text().strip()
        p = closed('after', group)
        unit = json.loads((OUT / 'unit-owner.json').read_text()) if (OUT / 'unit-owner.json').exists() else None
        if unit is not None:
            assert unit['group'] == group and gone(unit)
        lock_held(owner)
        assert identity(owner['pid']) == {k: owner[k] for k in ('pid', 'start', 'group')}
        native('parent-after')
        source_after = source_bytes('after')
        assert source_after == json.loads((OUT / 'source-before.json').read_text())
        after = inputs()
        save('inputs.after.json', after)
        before = json.loads((OUT / 'inputs.before.json').read_text())
        expected = before | ({FIXTURE: hashlib.sha256(b'unchanged\n').hexdigest()} if FIXTURE in after else {})
        source_ok = after == expected
        frozen = json.loads((OUT / 'driver.before.json').read_text())
        driver_ok = all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in frozen.items())
        result = int(result != 0 or not source_ok or not driver_ok or unit is None or not (OUT / 'unit-result.json').is_file()
                     or p['ActiveState'] != 'inactive' or p['SubState'] != 'dead' or (p['LoadState'] == 'loaded' and p['Result'] != 'success') or time.monotonic() > end)
        save('closed.json', {'unitClosed': True, 'parentLockHeld': True, 'sourceStable': source_ok,
                             'driverStable': driver_ok, 'result': result, 'elapsedNormalSeconds': 90 - (end - time.monotonic())})
    except BaseException as error:
        try:
            save('unknown.json', {'error': repr(error), 'rootRecoveryRequired': True})
            print('ROOT RECOVERY REQUIRED. Outside owner retains flock. Do not allocate another heavy slot.', flush=True)
        finally:
            while True:
                signal.pause()
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    save('unlocked.json', {'pid': owner['pid'], 'lock': owner['lock'], 'result': result})
    return result


def release_body():
    owner = json.loads((OUT / 'owner.json').read_text())
    closed_receipt = json.loads((OUT / 'closed.json').read_text())
    unlocked = json.loads((OUT / 'unlocked.json').read_text())
    assert closed_receipt['unitClosed'] and gone(owner) and unlocked['lock'] == owner['lock']
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW)
    st = os.fstat(fd)
    assert [st.st_dev, st.st_ino] == owner['lock']
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    save('release.json', {'parentExited': True, 'sameInodeReacquiredAndReleased': True, 'lock': owner['lock'], 'result': unlocked['result']})
    return unlocked['result']


if __name__ == '__main__':
    os.chdir(REPO)
    if sys.argv[1:] == ['owner']:
        raise SystemExit(owner_body())
    if sys.argv[1:] == ['unit']:
        unit_body()
    elif sys.argv[1:] == ['release']:
        raise SystemExit(release_body())
    elif sys.argv[1:] != ['owner']:
        raise SystemExit('exact owner, unit, or release mode required')
