# Fresh daemon attempt and root recovery

The separately granted fresh attempt failed on an owned namespace metadata read after native Info succeeded.
The source was `a8fb2dadb9aa857471d96778009c868aa42a5c2f` throughout execution.
Nonce `18ec13b3d43234b8ab4f79fbc49e0c1d`, its fixed intent, and private P/R paths are consumed forever.
Preserve them unchanged and never rerun the archived commands.
The earlier b7 identity and evidence remain unchanged.

## Observed result

Ordinary preflight passed.
The native parent enforced two CPUs, 4 GiB, zero swap, and 512 tasks before daemon birth.
The actual Info unit completed and native `StandardOutputFile` and `StandardErrorFile` produced separate files.
The retained JSON reports Docker 29.9.0, zero images and containers, the private data root, systemd cgroup v2, the containerd snapshotter, and rootless, seccomp, and cgroup namespace security fields.
The helper passed its `check_info` assertions before actor collection.

Actor collection then failed with `PermissionError` on `/proc/915847/ns/mnt`.
The launcher exited one, with no edit, retry, privilege escalation, alternate namespace access, or cleanup.
All 13,725 source/native/bundle byte-map entries and both commands' guard maps stayed unchanged.
The denied read was never retried.
Actual Info success does not establish full actor security, managed-containerd identity, detached-nsfs observations, namespace reference closure, or normal helper teardown.

## Independent recovery

Root stopped the exact recorded invocations through the existing native `owned_job` and `StopUnit` APIs.
Successful stop jobs were `/org/freedesktop/systemd1/job/5452` for Info, `/org/freedesktop/systemd1/job/5453` for the daemon, and `/org/freedesktop/systemd1/job/5454` for the slice.
Root recorded all three units as absent, both owned cgroups absent, eight recorded PID/start identities gone, five recorded process groups gone, and four owned sockets absent.
It observed 1,460 live samples and eight actual lock refusals, then independently acquired and released canonical lock device 54, inode 4045.

The [coordinator closure](fresh-attempt-root-closed.json) preserves these observations and their limits.
The distinct fixed root companion is included byte for byte in the archive.
Both accept recovery closure only, with qualification acceptance false.
Root stop jobs do not prove the helper's normal teardown or keeper-loss behavior.
Outside namespace holders remain unmeasured under the explicit assumption that no external actor acquires a namespace reference.

## Retained evidence

The [evidence archive](fresh-attempt-evidence.tar.gz) has 122 regular files.
Its internal manifest covers the other 121 members.
It preserves the complete produced command bundle, literal argv, preflight, traceback, guard and snapshot maps, primary intent and sidecars, actual Info output, root live observations, exact recovery stop events, and both root companions.
It also includes source preparation, the separately accepted 28-case offline archive and root closure, and 17 selected source byte pairs recovered from the native snapshots.
The nested offline archive retains its 250 regular files and thirteen declared source byte pairs.
The commands retain original absolute paths and are historical evidence only.

The full 13,046 source/native content blobs remain local at `/home/zack/.codex/orchestrate/vespiary-goal330/reviews/daemon-fresh-identity-native-ctx-e80eaa86a2f9/blobs`.
Root verified those actual blobs against the retained maps.
The portable archive omits the full repository and installed-native blobs.
It is neither a complete repository/native backup nor proof of a reproduced native build.

Verify published bytes from the repository root.

```sh
sha256sum -c docs/dev/verify-runtime-20261020/fresh-attempt-evidence.sha256
evidence_dir=$(mktemp -d)
tar -xzf docs/dev/verify-runtime-20261020/fresh-attempt-evidence.tar.gz -C "$evidence_dir"
cd "$evidence_dir"
sha256sum -c manifest.sha256
```

No source fix, new attempt, installer, image, container, Go validation, PR, integration, or Goal acceptance follows from this publication.
Full `make verify` remains mandatory before product Go review.
Root will assign a separate supported-API investigation.
