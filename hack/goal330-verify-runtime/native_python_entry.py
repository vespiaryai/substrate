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
import importlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


HERE = Path(__file__).resolve().parent
PROFILE = HERE.parents[1] / "docs/dev/verify-runtime-20261020/native-python-profile.json"
MAX_FILE = 134217728
MAX_TOTAL = 536870912
STDLIB = ("dataclasses", "fcntl", "hashlib", "json", "os", "pathlib", "re", "signal", "stat",
          "subprocess", "time", "tomllib", "importlib", "sys", "resource")
LOADED_SOURCES = {}
CHECKED_DOCUMENTS = {}
REVIEWED_DIGESTS = {}


def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise RuntimeError("profile input exceeds bound or is not regular")
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise RuntimeError("profile input exceeds bound")
    return body


class ReviewedSource(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        body = read_bounded(Path(self.path), 1048576)
        digest = hashlib.sha256(body).hexdigest()
        if REVIEWED_DIGESTS.get(self.path) != digest:
            raise RuntimeError("explicit module source buffer differs from reviewed input")
        LOADED_SOURCES[self.path] = {"size": len(body), "sha256": digest, "raw": body.hex()}
        return self.source_to_code(body, self.path)


def load_file(name, path, package=False):
    loader = ReviewedSource(name, str(path)) if path.suffix == ".py" else None
    spec = importlib.util.spec_from_file_location(
        name, path, loader=loader, submodule_search_locations=[str(path.parent)] if package else None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def checked_profile(authority="holder"):
    if not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode or "site" in sys.modules:
        raise RuntimeError("native import entry requires isolated no-site/no-bytecode execution")
    raw = read_bounded(PROFILE, 1048576)
    CHECKED_DOCUMENTS[str(PROFILE)] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "raw": raw.hex()}
    profile = json.loads(raw)
    if list(sys.path) != profile["stdlib_search"]:
        raise RuntimeError("native stdlib search differs from reviewed profile")
    for directory, names in profile["membership"].items():
        actual = []
        for path in Path(directory).iterdir():
            actual.append(path.name)
            if len(actual) > 4096:
                raise RuntimeError("native search membership exceeds bound")
        if sorted(actual) != names:
            raise RuntimeError("native search membership changed")
    for name in profile["required_absences"]:
        if Path(name).exists() or Path(name).is_symlink():
            raise RuntimeError("native import profile required absence changed")
    remaining = MAX_TOTAL
    for name, digest in profile["files"].items():
        body = read_bounded(Path(name), min(MAX_FILE, remaining))
        remaining -= len(body)
        if hashlib.sha256(body).hexdigest() != digest:
            raise RuntimeError("native Python compiled/module/library/config input changed")
        REVIEWED_DIGESTS[name] = digest
    manifest = PROFILE.with_name("native-api-inputs.sha256")
    raw = read_bounded(manifest, 1048576)
    CHECKED_DOCUMENTS[str(manifest)] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "raw": raw.hex()}
    for line in raw.decode().splitlines():
        digest, name = line.split("  ", 1)
        path = Path(name)
        if not path.is_absolute():
            path = HERE.parents[1] / path
        body = read_bounded(path, min(MAX_FILE, remaining))
        remaining -= len(body)
        if hashlib.sha256(body).hexdigest() != digest:
            raise RuntimeError("owner source/native/oracle manifest changed before loading")
        REVIEWED_DIGESTS[str(path)] = digest
    if authority == "import-only":
        if profile.get("import_inputs_reviewed") is not True:
            raise RuntimeError("import-only inputs remain incomplete and unreviewed")
    elif profile["application_enabled"] is not True or profile.get("operations", {}).get(authority) is not True:
        raise RuntimeError("native profile is source-unproved; separate operation proof required")
    return profile


def load_owners(profile, native_packages):
    for name in STDLIB:
        importlib.import_module(name)
    if native_packages:
        for name, path, package in profile["modules"]:
            load_file(name, Path(path), package)
        importlib.import_module("dbus.mainloop.glib")
        importlib.import_module("gi.repository.GLib")
    load_file("native_client_entry", HERE / "native_client_entry.py")
    if native_packages:
        load_file("systemd_job", HERE / "systemd_job.py")
    return load_file("native_api_observer", HERE / "native_api_observer.py")


def import_only():
    profile = checked_profile("import-only")
    load_owners(profile, True)
    modules = {}
    for name, module in sorted(sys.modules.items()):
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        row = {"origin": origin, "search": list(getattr(module, "__path__", []))}
        if origin and origin.endswith(tuple(importlib.machinery.EXTENSION_SUFFIXES)):
            body = read_bounded(Path(origin), MAX_FILE)
            row.update(size=len(body), sha256=hashlib.sha256(body).hexdigest())
        modules[name] = row
    report = json.dumps({"kind": "import-only", "application_enabled": profile["application_enabled"],
                         "search": list(sys.path), "modules": modules, "source_buffers": LOADED_SOURCES,
                         "checked_documents": CHECKED_DOCUMENTS}, sort_keys=True).encode()
    if len(report) > 1048576:
        raise RuntimeError("import-only evidence exceeds bound")
    sys.stdout.buffer.write(report + b"\n")


def main(mode, nonce=None):
    if mode == "import-only" and nonce is None:
        return import_only()
    if mode not in ("holder", "finite", "recheck") or nonce is None:
        raise RuntimeError("mode outside fixed owner-local operation")
    profile = checked_profile(mode)
    native = load_owners(profile, mode != "holder")
    attempt = native.Attempt(nonce)
    if mode == "holder":
        return native.hold_attempt(attempt)
    native.setup_native()
    if mode == "recheck":
        return attempt.recheck()
    pending = native.strict_json(native.read_bounded(attempt.receipt, native.MAX_RESULT), native.MAX_RESULT)
    owner = native.restore_observation({"owner": pending["owner"], "source": pending["source"],
                                       "host": {}, "mounts": pending["mounts"],
                                       "intents": [], "units": [], "processes": []}).owner
    if native.process_identity(owner.pid, owner) != owner:
        raise RuntimeError("finite child cannot bind the original live holder")
    fd = os.open(native.LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
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


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("expected import-only, or holder/finite/recheck and assigned nonce")
    main(*sys.argv[1:])
