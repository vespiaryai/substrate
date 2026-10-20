# First daemon attempt and recovery

The first native attempt failed when systemd rejected the Info unit's transient `StandardOutput=file:.../info.json` property.
Ordinary preflight passed, the parent enforced two CPUs, 4 GiB, zero swap, and 512 tasks, and daemon startup reached the private socket.
No successful Info job or Info observation followed.
The source was `ba85de0b26729d288d0f44c50d133bd30724b003` throughout the attempt.

Root independently recovered the failed attempt after the daemon's native runtime limit expired.
It recorded daemon result `timeout`, stopped the retained slice with successful job `/org/freedesktop/systemd1/job/5095`, and verified exact native closure and release of lock device 54, inode 4045.
The [root attestation](first-attempt-root-closed.json) records the observations and their limits.
Its acceptance remains false.

The fixed nonce `b7a6306f20fabfaab02a29eaecf04531` and its intent are consumed.
Keep the intent, failure receipts, and private P/R trees unchanged.
Never rerun the archived commands or bootstrap helper with that identity.
The commands inside the archive describe the original attempt and retain their original absolute paths.

## Retained evidence

The [evidence archive](first-attempt-evidence.tar.gz) contains 80 regular files.
It retains the literal commands, preflight, traceback, original source/native byte maps, fixed pending/failure/unit receipts, reports, and all three root recovery records.
Both distinct root closure companions are included byte for byte.
It also includes the accepted 26-case offline root attestation, eleven actual current-source files and the canonical guard before and after the attempt.
The archive's manifest covers its other 79 members.

The before/after maps cover 13,695 frozen paths and match exactly.
Each command's canonical guard retained 13,618 unchanged repository entries.
Preflight exited zero and bootstrap exited one.
The original complete snapshot retains 13,019 verified content blobs under `/home/zack/.codex/orchestrate/vespiary-goal330/reviews/daemon-owned-scope-first-attempt-ctx-e8d010585409`.
Those full unchanged-repository and installed-native blobs remain local and are omitted from this archive.
Their original maps and digest manifest are included.
Checking this archive verifies its published bytes, not the omitted native blobs or a reproduced native build.

Check the archive from the repository root.

```sh
sha256sum -c docs/dev/verify-runtime-20261020/first-attempt-evidence.sha256
evidence_dir=$(mktemp -d)
tar -xzf docs/dev/verify-runtime-20261020/first-attempt-evidence.tar.gz -C "$evidence_dir"
cd "$evidence_dir"
sha256sum -c manifest.sha256
```

## Qualification limits

The current 22 daemon and four job-helper tests passed before this attempt, with root acceptance and guard controls `0, 97, 0`.
The older fourteen-test receipt still belongs to its historical source.
Neither result accepts this failed native attempt.
Private Info security and zero-object checks, managed-containerd identity, detached-nsfs observations, and normal helper teardown remain unproved.
Root recorded daemon PID absence but did not sample its start time or a complete live descendant/namespace set before Info failed.
Owned cgroup closure relies on the reviewed native inheritance contract.
Outside namespace holders remain unmeasured under the explicit no-external-acquisition assumption.
Recovery permits later scheduling and does not qualify keeper loss, product Go behavior, full `make verify`, or Goal completion.
