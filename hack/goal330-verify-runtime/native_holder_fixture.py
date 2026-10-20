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
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time


HERE = Path(__file__).resolve().parent
CASES = ("clean", "failed", "nonzero", "signal", "missing", "malformed", "oversized",
         "source-drift", "receipt-error", "timeout", "recheck-timeout", "recheck-nonzero")


def load(name):
    path = HERE / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.fstat(stream.fileno()).st_size > 1048576:
            raise RuntimeError("fixture source exceeds regular-file bound")
        body = stream.read(1048577)
    if len(body) > 1048576:
        raise RuntimeError("fixture source exceeds bound")
    exec(compile(body, str(path), "exec"), module.__dict__)
    return module


def await_file(path):
    deadline = time.monotonic() + 5
    while not path.exists():
        if time.monotonic() > deadline:
            raise RuntimeError("fixture handshake deadline")
        time.sleep(0.01)


def block():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        signal.pause()


def main(mode, case, directory):
    if mode not in ("holder", "finite", "recheck") or case not in CASES:
        raise RuntimeError("outside fixed fixture selection")
    root = Path(directory)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RuntimeError("fixture needs an existing owned absolute directory")
    load("native_client_entry")
    native = load("native_api_observer")
    native.LOCK = root / "canonical-lock"
    native.REVIEWS = root
    source = root / "source"
    native.host_state = lambda: {"native-metadata-boundary": "owned fixture only"}
    native.holder_budget = lambda owner: [{"fixture": "no native allocation", "cgroup": owner.cgroup}]
    native.frozen_inputs = lambda: native.digest_map((source,))
    native.Attempt.p = property(lambda self: root / "persistent")
    native.Attempt.r = property(lambda self: root / "runtime")
    native.Attempt.child_argv = lambda self, operation: [
        "/usr/bin/python3", "-I", "-S", "-B", str(Path(__file__).resolve()), operation, case, str(root)]
    attempt = native.Attempt("00000000000000000000000000000001")
    original_wait = native.wait_finite
    native.wait_finite = lambda attempt, child, identity, operation, seconds: original_wait(
        attempt, child, identity, operation,
        1 if (case, operation) in (("timeout", "finite"), ("recheck-timeout", "recheck")) else 8)
    if mode == "holder":
        if case == "receipt-error":
            native.append_receipt = lambda *args: (_ for _ in ()).throw(OSError("owned receipt failure"))
            original_park = native.park_unknown
            def park(attempt, error):
                (root / "receipt-error-ready").write_bytes(b"retaining fixture custody\n")
                original_park(attempt, error)
            native.park_unknown = park
        status = native.hold_attempt(attempt)
        native.write_evidence(root / "holder-return.json", json.dumps({"status": status}).encode())
        return
    pending = native.strict_json(native.read_bounded(attempt.receipt, native.MAX_RESULT), native.MAX_RESULT)
    fd = os.open(native.LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        if [metadata.st_dev, metadata.st_ino] != pending["lock"]:
            raise RuntimeError("fixture contention inode mismatch")
        try:
            inherited = os.fstat(pending["descriptor"])
        except OSError:
            inherited = None
        if fd != pending["descriptor"] and inherited is not None and (
                inherited.st_dev, inherited.st_ino) == (metadata.st_dev, metadata.st_ino):
            raise RuntimeError("canonical descriptor crossed exec")
        try:
            native.fcntl.flock(fd, native.fcntl.LOCK_EX | native.fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise RuntimeError("fixture holder lost custody")
    finally:
        os.close(fd)
    native.append_receipt(root / f"{mode}-contention.json", {"inode": pending["lock"], "inherited": False})
    await_file(attempt.receipt.with_suffix(f".{mode}-child.json"))
    native.Attempt.stop = lambda self, unit: "/job/fixture-stop"
    native.Attempt.terminal = lambda self, unit: {"unit": unit.unit, "state": "fixture-closed"}
    native.Attempt.closed_objects = lambda self, parent, actors: None
    if mode == "recheck":
        if case == "recheck-timeout":
            native.Attempt.terminal = lambda self, unit: block()
        attempt.recheck()
        if case == "recheck-nonzero":
            raise SystemExit(23)
        return
    owner = native.restore_observation({"owner": pending["owner"], "source": pending["source"],
                                       "host": {}, "mounts": pending["mounts"],
                                       "intents": [], "units": [], "processes": []}).owner
    def observe(self, observation, deadline):
        parent = native.UnitIdentity(owner.boot, self.units[0], b"f" * 16, "/fixture-native-parent", "/job/fixture")
        observation.intents.append(parent.unit)
        observation.units.append(parent)
        if case == "failed":
            raise RuntimeError("owned qualification failure")
        if case == "source-drift":
            source.write_bytes(b"changed fixture source")
        if case == "timeout":
            block()
    native.Attempt.observe = observe
    if case in ("missing", "malformed", "oversized"):
        if case != "missing":
            attempt.receipt.with_suffix(".finite-result.json").write_bytes(
                b"{" if case == "malformed" else b"x" * (native.MAX_RESULT + 1))
        return
    attempt.finite(owner, pending["source"])
    if case == "nonzero":
        raise SystemExit(17)
    if case == "signal":
        os.kill(os.getpid(), signal.SIGKILL)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("expected fixed holder fixture mode, case and owned directory")
    main(*sys.argv[1:])
