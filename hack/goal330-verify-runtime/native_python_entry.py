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
import sys


HERE = Path(__file__).resolve().parent
PROFILE = HERE.parents[1] / "docs/dev/verify-runtime-20261020/native-python-profile.json"


def load_file(name, path, package=False):
    spec = importlib.util.spec_from_file_location(
        name, path, submodule_search_locations=[str(path.parent)] if package else None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    if path.suffix == ".py":
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    else:
        spec.loader.exec_module(module)
    return module


def checked_profile():
    if not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode or "site" in sys.modules:
        raise RuntimeError("native import entry requires isolated no-site/no-bytecode execution")
    profile = json.loads(PROFILE.read_bytes())
    if list(sys.path) != profile["stdlib_search"]:
        raise RuntimeError("native stdlib search differs from reviewed profile")
    for directory, names in profile["membership"].items():
        if sorted(path.name for path in Path(directory).iterdir()) != names:
            raise RuntimeError("native search membership changed")
    for name in profile["required_absences"]:
        if Path(name).exists() or Path(name).is_symlink():
            raise RuntimeError("native import profile required absence changed")
    for name, digest in profile["files"].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("native Python compiled/module/library/config input changed")
    if profile["application_enabled"] is not True:
        raise RuntimeError("native profile is source-unproved; separate complete loading review/proof required")
    manifest = PROFILE.with_name("native-api-inputs.sha256")
    for line in manifest.read_text().splitlines():
        digest, name = line.split("  ", 1)
        path = Path(name)
        if not path.is_absolute():
            path = HERE.parents[1] / path
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("owner source/native/oracle manifest changed before loading")
    return profile


def main(mode, nonce):
    profile = checked_profile()
    for name, path, package in profile["modules"]:
        load_file(name, Path(path), package)
    load_file("native_client_entry", HERE / "native_client_entry.py")
    load_file("systemd_job", HERE / "systemd_job.py")
    native = load_file("native_api_observer", HERE / "native_api_observer.py")
    attempt = native.Attempt(nonce)
    if mode == "holder":
        return native.hold_attempt(attempt)
    if mode == "finite":
        pending = native.strict_json(native.read_bounded(attempt.receipt, native.MAX_RESPONSE))
        owner = native.restore_observation({"owner": pending["owner"], "source": pending["source"],
                                            "host": {}, "mounts": pending["mounts"],
                                            "intents": [], "units": [], "processes": []}).owner
        if native.process_identity(owner.pid, owner) != owner:
            raise RuntimeError("finite child cannot bind the original live holder")
        fd = os.open("/tmp/vespiary-heavy-validation.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            import fcntl
            metadata = os.fstat(fd)
            if [metadata.st_dev, metadata.st_ino] != pending["lock"]:
                raise RuntimeError("contention witness is not the canonical inode")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
                raise RuntimeError("original holder does not retain canonical contention")
        finally:
            os.close(fd)
        return attempt.finite(owner, pending["source"])
    raise RuntimeError("mode outside fixed owner-local operation")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("expected holder or finite and a separately assigned nonce")
    main(sys.argv[1], sys.argv[2])
