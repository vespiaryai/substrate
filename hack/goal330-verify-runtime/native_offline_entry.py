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
import stat
import sys


HERE = Path(__file__).resolve().parent
IDS = (
    "test_native_api_observer.NativeObserverTest.test_normal_observer_and_paired_refusals",
    "test_native_api_observer.NativeObserverTest.test_api_and_identity_refuse_before_later_mutation",
    "test_native_api_observer.NativeObserverTest.test_strict_response_rejects_duplicate_trailing_nonfinite_and_wrong_shapes",
    "test_native_api_observer.NativeObserverTest.test_managed_containerd_metadata_is_exact",
    "test_native_api_observer.NativeObserverTest.test_docker_info_preserves_zero_objects_endpoint_and_defaults",
    "test_native_api_observer.NativeObserverTest.test_required_metadata_denial_escape_and_pid_reuse",
    "test_native_api_observer.NativeObserverTest.test_positive_closure_requires_cgroup_process_group_and_socket_absence",
    "test_native_api_observer.NativeObserverTest.test_bounds_refuse_before_daemon_birth",
    "test_native_api_observer.NativeObserverTest.test_changed_invocation_refuses_stop",
    "test_native_api_observer.NativeObserverTest.test_native_lifetimes_and_single_bounded_standard_client",
    "test_native_api_observer.NativeObserverTest.test_consumed_or_missing_identity_refuses",
    "test_native_api_observer.NativeJobRefusalTest.test_lost_failed_and_unrelated_jobs_cannot_complete",
    "test_native_api_observer.CustodyAndEntryTest.test_unknown_receipt_failure_retains_actual_descriptor",
    "test_native_api_observer.CustodyAndEntryTest.test_actual_child_does_not_inherit_owned_descriptor",
    "test_native_api_observer.CustodyAndEntryTest.test_partial_start_is_unknown_and_parent_does_not_close_first",
    "test_native_api_observer.CustodyAndEntryTest.test_receipt_error_prevents_native_start",
    "test_native_api_observer.CustodyAndEntryTest.test_short_client_completion_joins_actual_witness",
    "test_native_api_observer.JobSetupFinalizerTest.test_setup_and_early_signal_finalizers",
    "test_native_api_observer.NativeInputProfileTest.test_native_loading_refuses_unproved_changed_or_shadow_inputs",
    "test_native_api_observer.NativeInputProfileTest.test_import_only_does_not_construct_attempt_or_call_operations",
    "test_native_api_observer.OwnedHolderTest.test_clean_closure_releases_actual_inode",
    "test_native_api_observer.OwnedHolderTest.test_failed_qualification_releases_after_closure",
    "test_native_api_observer.OwnedHolderTest.test_nonzero_after_result_fails_qualification",
    "test_native_api_observer.OwnedHolderTest.test_signal_after_result_fails_qualification",
    "test_native_api_observer.OwnedHolderTest.test_missing_result_retains_actual_holder",
    "test_native_api_observer.OwnedHolderTest.test_malformed_result_retains_actual_holder",
    "test_native_api_observer.OwnedHolderTest.test_oversized_result_retains_actual_holder",
    "test_native_api_observer.OwnedHolderTest.test_source_drift_fails_but_closes",
    "test_native_api_observer.OwnedHolderTest.test_receipt_error_retains_actual_holder",
    "test_native_api_observer.OwnedHolderTest.test_nonresponsive_finite_child_retains_holder",
    "test_native_api_observer.OwnedHolderTest.test_nonresponsive_recheck_retains_holder_recovery",
    "test_native_api_observer.OwnedHolderTest.test_nonzero_recheck_after_result_retains_holder",
    "test_native_api_observer.OwnedHolderTest.test_regular_read_and_result_writer_enforce_limits",
    "test_native_api_observer.OwnedHolderTest.test_actual_producer_stops_at_file_limit",
    "test_systemd_job.OwnedJobTest.test_requires_exact_successful_job",
    "test_systemd_job.OwnedJobTest.test_stop_wait_outlasts_native_fifteen_second_stop",
    "test_systemd_job.OwnedJobTest.test_rejects_failed_job",
    "test_systemd_job.OwnedJobTest.test_other_job_cannot_complete_owned_job",
)
EXPECTED_COUNT = 38
PROOF = Path("/home/zack/.codex/orchestrate/vespiary-goal330/reviews/daemon-native-source-corrections/offline-proof")


def load_entry():
    path = HERE / "native_python_entry.py"
    spec = importlib.util.spec_from_file_location("native_python_entry", path)
    entry = importlib.util.module_from_spec(spec)
    sys.modules["native_python_entry"] = entry
    with path.open("rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1048576:
            raise RuntimeError("fixed entry source exceeds regular-file bound")
        body = stream.read(1048577)
    if len(body) > 1048576:
        raise RuntimeError("fixed entry source exceeds bound")
    exec(compile(body, str(path), "exec"), entry.__dict__)
    return entry


def snapshot(entry, destination):
    destination.mkdir(mode=0o700)
    manifest = entry.PROFILE.with_name("native-api-inputs.sha256")
    raw = entry.read_bounded(manifest, 1048576)
    profile_raw = entry.read_bounded(entry.PROFILE, 1048576)
    profile = json.loads(profile_raw)
    paths = {manifest, entry.PROFILE}
    for line in raw.decode().splitlines():
        _digest, name = line.split("  ", 1)
        path = Path(name)
        paths.add(path if path.is_absolute() else HERE.parents[1] / path)
    paths.update(Path(name) for name in profile["files"])
    if len(paths) > 4096:
        raise RuntimeError("offline input union exceeds bound")
    result = {"files": {}, "links": {}, "membership": {}, "absences": {}}
    remaining = entry.MAX_TOTAL - len(raw) - len(profile_raw)
    if remaining < 0:
        raise RuntimeError("offline documents exceed aggregate bound")
    for path in sorted(paths):
        if path == manifest:
            body = raw
        elif path == entry.PROFILE:
            body = profile_raw
        else:
            body = entry.read_bounded(path, min(remaining, entry.MAX_FILE))
            remaining -= len(body)
        digest = hashlib.sha256(body).hexdigest()
        metadata = path.stat()
        result["files"][str(path)] = {"sha256": digest, "size": len(body), "mode": metadata.st_mode,
                                       "uid": metadata.st_uid, "gid": metadata.st_gid,
                                       "device": metadata.st_dev, "inode": metadata.st_ino,
                                       "mtime_ns": metadata.st_mtime_ns}
        for index in range(0, max(1, len(body)), 4194304):
            archive = destination / f"{len(result['files']):04d}-{index // 4194304:04d}-{digest}.raw"
            with archive.open("xb") as stream:
                stream.write(body[index:index + 4194304])
    for directory in profile["membership"]:
        names = []
        with os.scandir(directory) as entries:
            for item in entries:
                if len(names) >= 4096:
                    raise RuntimeError("offline membership exceeds bound")
                names.append(item.name)
        result["membership"][directory] = sorted(names)
    for name in profile["required_absences"]:
        result["absences"][name] = not os.path.lexists(name)
    pending = list(paths) + [Path(name) for name in profile["membership"]] + [
        Path(name).parent for name in profile["required_absences"]]
    seen = set()
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        if len(seen) >= 32768:
            raise RuntimeError("offline link census exceeds bound")
        seen.add(path)
        if path.is_symlink():
            target = os.readlink(path)
            if len(os.fsencode(target)) > 4096 or len(result["links"]) >= 4096:
                raise RuntimeError("offline link target exceeds bound")
            metadata = path.lstat()
            result["links"][str(path)] = {"target": target, "mode": metadata.st_mode,
                                          "uid": metadata.st_uid, "gid": metadata.st_gid,
                                          "device": metadata.st_dev, "inode": metadata.st_ino,
                                          "mtime_ns": metadata.st_mtime_ns}
            pending.append(Path(os.path.abspath(path.parent / target)))
        if path != path.parent:
            pending.append(path.parent)
    encoded = json.dumps(result, sort_keys=True)
    if len(encoded.encode()) > 1048576:
        raise RuntimeError("offline snapshot map exceeds bound")
    with (destination / "map.json").open("x") as stream:
        stream.write(encoded)
    if (result["membership"] != profile["membership"] or not all(result["absences"].values())):
        raise RuntimeError("offline profile membership or absence changed")
    return result


def require_stable(before, after):
    if before != after:
        raise SystemExit(97)


def guard_fixture(changed):
    entry = load_entry()
    directory = PROOF.parent / "guard-proof"
    path = directory / "source"
    if changed:
        directory.mkdir(mode=0o700)
        with path.open("xb") as stream:
            stream.write(b"fixed source\n")
        with (directory / "profile.json").open("x") as stream:
            json.dump({"files": {str(path): hashlib.sha256(b"fixed source\n").hexdigest()},
                       "membership": {}, "required_absences": []}, stream, sort_keys=True)
        with (directory / "native-api-inputs.sha256").open("x") as stream:
            stream.write("")
    elif entry.read_bounded(path, 1024) != b"fixed source\n":
        raise RuntimeError("restore the owned guard fixture separately before stable proof")
    entry.PROFILE = directory / "profile.json"
    label = "refusal" if changed else "stable"
    before = snapshot(entry, directory / f"{label}-before")
    if changed:
        path.write_bytes(b"changed source\n")
    after = snapshot(entry, directory / f"{label}-after")
    if str(path) not in before["files"] or str(path) not in after["files"]:
        raise RuntimeError("guard fixture omitted the profile-only input")
    print(json.dumps({"before": before, "after": after}, sort_keys=True))
    require_stable(before, after)


def suite():
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (4194304, 4194304))
    entry = load_entry()
    profile = entry.checked_profile("import-only")
    if profile.get("offline_reviewed") is not True:
        raise RuntimeError("fixed offline selection is not reviewed for execution")
    before = snapshot(entry, PROOF / "before")
    entry.load_owners(profile, True)
    import unittest
    for name in ("test_native_api_observer", "test_systemd_job"):
        entry.load_file(name, HERE / f"{name}.py")
    selected = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in IDS)
    if len(IDS) != EXPECTED_COUNT or len(set(IDS)) != EXPECTED_COUNT or selected.countTestCases() != EXPECTED_COUNT:
        raise RuntimeError("fixed test IDs or multiplicity differ")
    result = unittest.TextTestRunner(verbosity=2).run(selected)
    after = snapshot(entry, PROOF / "after")
    stable = after == before
    accepted = (result.testsRun == EXPECTED_COUNT and result.wasSuccessful() and not result.skipped
                and not result.expectedFailures and not result.unexpectedSuccesses and stable)
    print(json.dumps({"ids": IDS, "expected_count": EXPECTED_COUNT, "tests_run": result.testsRun,
                      "skips": result.skipped, "expected_failures": len(result.expectedFailures),
                      "failures": len(result.failures), "errors": len(result.errors),
                      "source_stable": stable, "accepted": accepted}, sort_keys=True))
    require_stable(before, after)
    if not accepted:
        raise SystemExit(1)


def outside():
    import fcntl
    import signal
    import stat
    import subprocess
    entry = load_entry()
    profile = entry.checked_profile("import-only")
    if profile.get("offline_reviewed") is not True:
        raise RuntimeError("fixed offline outside invocation is not reviewed")
    native = entry.load_owners(profile, False)
    boot = native.read_bounded(native.PROC / "sys/kernel/random/boot_id", native.MAX_FILE).decode().strip()
    group = native.read_bounded(native.PROC / "self/cgroup", native.MAX_FILE).decode().strip()
    if not group.startswith("0::"):
        raise RuntimeError("offline outside requires unified native placement")
    owner = native.process_identity(os.getpid(), native.UnitIdentity(boot, "offline-outside", b"", group[3:], ""))
    budget = native.holder_budget(owner)
    PROOF.mkdir(mode=0o700)
    lock = Path("/tmp/vespiary-heavy-validation.lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    metadata = os.fstat(fd)
    identity = (metadata.st_dev, metadata.st_ino)
    current = lock.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 1000 or os.get_inheritable(fd)
            or (current.st_dev, current.st_ino) != identity):
        os.close(fd)
        raise RuntimeError("offline outside descriptor identity mismatch")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    def interrupted(_signal, _frame):
        raise InterruptedError("offline outside interruption retains custody")
    child = None
    try:
        signal.signal(signal.SIGTERM, interrupted)
        native.append_receipt(PROOF / "outside-pending.json", {"owner": owner, "budget": budget,
                              "lock": identity, "descriptor": fd, "inheritable": False,
                              "executable": os.readlink(native.PROC / "self/exe"), "finite_seconds": 120})
        with (PROOF / "stdout").open("xb") as stdout, (PROOF / "stderr").open("xb") as stderr:
            child = subprocess.Popen(["/usr/bin/python3", "-I", "-S", "-B", str(Path(__file__).resolve()), "suite"],
                                     env={"PATH": "/usr/bin:/bin", "HOME": "/home/zack", "LC_ALL": "C", "LANG": "C"},
                                     close_fds=True, start_new_session=True, stdout=stdout, stderr=stderr)
            finite = native.process_identity(child.pid, native.UnitIdentity(boot, "offline-suite", b"", owner.cgroup, ""))
            native.append_receipt(PROOF / "outside-child.json", {"child": finite})
            class Receipt:
                receipt = PROOF / "outside-pending.json"
            exit_record = native.wait_finite(Receipt(), child, finite, "suite", 120)
            code = exit_record["returncode"]
        with (PROOF / "outside-result.json").open("x") as stream:
            json.dump({"pid": child.pid, "returncode": code, "lock": identity,
                       "ids": IDS, "expected_count": EXPECTED_COUNT}, stream, sort_keys=True)
        current = lock.lstat()
        if code != 0 or (current.st_dev, current.st_ino) != identity:
            raise RuntimeError("offline child failed or canonical identity changed")
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    except BaseException:
        try:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        except BaseException:
            pass
        while True:
            try:
                signal.pause()
            except BaseException:
                pass


if __name__ == "__main__":
    if sys.argv[1:] == ["outside"]:
        outside()
    elif sys.argv[1:] == ["suite"]:
        suite()
    elif sys.argv[1:] == ["guard-refusal"]:
        guard_fixture(True)
    elif sys.argv[1:] == ["guard-stable"]:
        guard_fixture(False)
    else:
        raise SystemExit("only the fixed outside/suite/guard fixture operations are supported")
