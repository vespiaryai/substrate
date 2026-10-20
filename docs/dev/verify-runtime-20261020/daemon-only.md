# Prepare one daemon-only rootless Docker attempt

This is an unrun source proposal based on `de861e9585cc3bc92fb0d87c0da37dee4ca765a2`.
The owned-scope correction starts at `fc52efc63a512cb98133cfe3fd9e31a068231bc6` and has no execution result.
Do not execute it before root inspects the actual source, hashes, commands, and remaining limits below.
This unit contains no Go invocation, registry operation, image acquisition, container operation, or network API creation.
Root owns the later finite proof and every subsequent compatibility, product, verification, and integration gate.

## Inspect the source unit

1. Read `hack/goal330-verify-runtime/daemon_bootstrap.py`, its tests, and the native job helper.
2. Check `daemon-owned-scope.sha256` from the repository root.
3. Compare the installed native files with `daemon-only-native.sha256`.
4. Read the pending receipt contract before granting any future heavy slot.

```sh
sha256sum -c docs/dev/verify-runtime-20261020/daemon-owned-scope.sha256
sha256sum -c docs/dev/verify-runtime-20261020/daemon-only-native.sha256
git diff de861e9585cc3bc92fb0d87c0da37dee4ca765a2 -- hack/goal330-verify-runtime docs/dev/verify-runtime-20261020
```

The older `evidence/manifest.sha256` and `daemon-only.sha256` remain frozen historical source identities.
The latter describes the source used by the retained mock qualification and failed same-UID preflight.
Use its retained source packet when inspecting those historical receipts. Its changed-source entries no longer match this worktree.
The new manifest records the owned-scope helper, paired fixtures, and proposal without rewriting those receipts.
All Go, product, vendor, image metadata, and certificate candidate bytes remain outside this change.

## Reserve the pending identity before execution

Hold the program's one heavy allocation for this attempt.
The allocation is two CPUs, 4 GiB, zero swap, and 512 tasks within the existing six-CPU/eight-GiB program budget.
The keeper performs small filesystem and read-only coordination operations outside the slice. All daemon, helper, and Docker CLI work starts inside it.

Root must check this exact receipt before granting another heavy slot after loss of the keeper.

```text
/home/zack/.codex/orchestrate/vespiary-goal330/reviews/daemon-only-pending-b7a6306f20fabfaab02a29eaecf04531.json
```

The keeper acquires `/tmp/vespiary-heavy-validation.lock` nonblocking.
It writes the pending receipt with `O_EXCL`, `O_NOFOLLOW`, a file fsync, and a parent-directory fsync before its first unit mutation.
The receipt records the fixed nonce, source hashes, boot, keeper PID/start time, units, private paths, endpoint, and 300-second proposal.
An existing receipt refuses another attempt before any unit or private-path creation.
Companion files append parent, daemon, observation, stopped, closed, or failed evidence under distinct exclusive names.
Inside the guarded body, the exception handler writes `.failed.json` and re-raises.
The entrypoint then exits and the kernel releases its flock descriptor.
The keeper does not park or remain alive to retain the lock after failure.
Failures before the guarded body, or failure to write the failed companion, can leave only the pending receipt.
Native SIGALRM or other process death also releases flock without guaranteeing a failed companion or cleanup.
Neither a free flock nor absent API is permission to grant another heavy slot.
Root must reconcile the same recorded identities if the attempt lacks positive closure or has a failed companion.
No new nonce, automatic retry, recovery daemon, queue, or supervisor exists.

## Inspect the native lifetimes

The slice sets `StopWhenUnneeded=false` explicitly and stays active through daemon teardown and positive postflight.
The keeper checks its actual cgroup files and records every ancestor before daemon birth.
The leaf must enforce at most two CPUs, 4294967296 memory bytes, zero swap, and 512 tasks.
The source records available controllers and subtree controls. Native child placement supplies the service boundary.

The daemon uses `Type=exec`, the exact slice, `Delegate=true`, `Restart=no`, and `KillMode=control-group`.
Its start timeout is 15 seconds, runtime maximum is 180 seconds, randomized extra runtime is zero, and stop timeout is 15 seconds.
The keeper refuses daemon startup when fewer than 210 seconds remain in the proposed 300-second attempt.
Its readiness wait is at most 30 seconds, with teardown reserved before the attempt deadline.
The Info unit uses `Type=oneshot`, `RemainAfterExit=true`, no delegation, and a ten-second start timeout.
Its explicit private Docker CLI exits before the Info job completes.
The Info unit can retain active/exited state with an empty cgroup. The source preserves its invocation identity without inventing an active PID.

The job helper subscribes to exact-unit `JobRemoved` before mutation and requires the returned job path with result `done`.
Its stop wait is now 20 seconds because a 15-second event wait cannot reliably outlast the daemon's native 15-second stop timeout.
Every D-Bus operation still has a five-second call timeout. A lost or failed job stops further unit mutations and retains uncertainty.
A native timeout bounds attempted termination. It does not prove exit of an uninterruptible kernel task or positive cleanup.
The keeper installs the default SIGALRM action and a 300-second native process alarm before its first mutation. Root must still prove actual expiry and postflight on the installed host.

## Inspect the fixed native composition

The nonce, P, R, S, daemon name, and private URI match the earlier inspected launcher proposal.
The additional Info service is `vesverifyb7a6306f20fabfaab02a29eaecf04531-info.service`.
The daemon configuration and scrubbed argv come directly from `daemon_config()` and `daemon_argv()`.
They preserve installed Docker 29.9.0, private managed containerd, pasta/implicit, and unchanged native security defaults.
Private `XDG_RUNTIME_DIR=R/xdg` prevents adoption of an existing user containerd socket.
`DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus` preserves the actual user bus.
No alternate runtime, embedded containerd, storage-driver fallback, security override, package transaction, user change, or shared daemon API is present.

The only Docker CLI argv follows. It runs through a native bounded Info unit with an empty private config and scrubbed environment.

```text
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/home DOCKER_CONFIG=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/docker-config /usr/bin/docker --config /home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/docker-config --host unix:///run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/docker.sock info --format {{json .}}
```

Info must report zero images and containers, the exact data root, native containerd snapshotter, systemd/cgroup v2, rootless, builtin seccomp, and cgroup namespaces.
The observer checks actual containerd TOML root/state/sockets and exact argv against the managed-daemon source contract.
It requires observed RootlessKit, dockerd, containerd, and pasta actors under the bounded slice.
It records PID/start time, PPID, cgroup, argv, namespaces, maps, status, contexts, listeners, mounts, and descriptors.
Any access denial, source contradiction, escaped actor, unexpected identity, or failed native check stops the attempt.

The owned set includes both services and every fork/exec descendant, including short-lived helpers and reparented children.
Ownership follows native pre-birth placement and inherited cgroup membership. It does not follow UID equality or one sampled PID list.
The finite operation assumes unrelated host actors do not acquire or receive namespace references.
Same-UID actors can access private state despite its 0700 directories. This operation does not establish isolation against them.
Outside holders remain unmeasured. Empty cgroups cannot prove universal namespace disappearance.

The [Moby supervisor source](https://github.com/moby/moby/blob/a5b58c94d334674eae3a3207d4f05417643a90d0/daemon/internal/containerd/server/supervisor/remote_daemon.go) derives the private paths and starts containerd with ordinary fork/exec inheritance.
The installed rootless launcher directly execs RootlessKit with the selected private state.
The [RootlessKit parent source](https://github.com/rootless-containers/rootlesskit/blob/v3.2.0/pkg/parent/parent.go) forks its child and only performs cgroup evacuation when that option is nonempty.
This launcher supplies no evacuation option or additional systemd placement API.
The source contract and actual native controls support scoped placement proof. They do not supply a universal history of every short-lived PID.

RootlessKit's native `rootlesskit/child_pid` identifies the child in the observed owned actor set.
The helper stats `/proc/<exact-child-pid>/root/<R>/rootlesskit/netns` without opening a namespace handle.
It binds the stat device and inode to the child's exact `nsfs` mount record, with PID/start time and cgroup checks before and after.
The detached netns can differ from every process leader's `ns/net`. It therefore needs its own recorded identity.
The parent source supplies that child-visible path. The child source creates its bind mount inside the child mount namespace.
The selected launcher uses `rslave`. Linux also reduces shared propagation when copying mounts into a less privileged mount namespace.
These source contracts support the expected lack of propagation into the observer's mount namespace.
Actual owned mount metadata and the observer's `/proc/self/mountinfo` before and after must agree with that deduction.
The keeper uses readlink, stat, and text metadata reads. It does not open or retain namespace FDs, join namespaces, or create mounts.
Its finite self fd-link check refuses any observed private namespace identity, including the detached netns.
The fd directory remains open during its own enumeration so its metadata handle is readable. No fd contents are read.

The retained origin packet is `design/daemon-namespace-scope-sources-ctx_94adfbabae66` under the program's external evidence directory.
Its manifest binds 22 pinned upstream or installed native files to exact hashes and origins.
The grounding is RootlessKit `parent.go:63,264-269,307-310`, `child.go:414-419,449-450,618-636`, and native `mount_namespaces.7:1067-1081`.
The investigation at `design/daemon-namespace-scope-investigation.md` records the containment argument and its limits.

## Prepare the next read-only preflight

Retain the failed preflight and all its source bytes unchanged. Its PID 3089 denial remains a failed historical access check.
Root must inspect new literal command bytes and a new evidence directory before granting a later preflight or attempt.
Keep the fixed nonce first-use checks for the pending intent, every raw companion, root closure companion, P, R, exact units, files, and jobs.
Reconcile every other pending attempt and its distinct root closure attestation before any heavy grant.
Check the new source manifest, unchanged installed native manifests, ordinary identity, host fingerprints, and keeper metadata.
Read only the keeper's own mount table and fd-link metadata during preflight. Do not enumerate `/proc` or test unrelated same-UID metadata access.
The owned actors do not yet exist, so preflight cannot qualify their later metadata access.

During the granted operation, use `GetUnitProcesses(S)` for owned actors.
Required reads are their exact `stat`, `cgroup`, `cmdline`, `status`, `uid_map`, `gid_map`, `attr/current`, `mountinfo`, `net/*`, namespace links, and fd-link metadata.
Also require the native `child_pid` and detached-netns stat through that exact owned child's root.
An owned metadata denial remains failed or unknown. Do not catch it as absence or silently skip the actor.
If such a denial proves essential, stop for a separately scoped supported read-only observer proposal.
That proposal must bind boot, exact PID/start time, cgroup, metadata paths, and before/after identity checks.
It must name any privilege and reversal needs. This source does not authorize sudo, security changes, or reading unrelated PID 3089.

## Prepare the future checks without running them now

Use the [owned-scope qualification proposal](daemon-owned-scope-proposal.md) for root's later test-scope decision.
It selects exactly the two test modules, preserves the canonical guard, and requires native validation-unit closure before lock release.
Dropin validation must release its heavy slot before root can grant this separate test attempt.
Neither this proposal nor the test source authorizes execution now.
Freeze actual source, test, guard, native, and proposed command bytes before and after the granted command.
A changed oracle invalidates the affected result. The proposal includes an owned-fixture guard-refusal control.
The installed XML test fails on a missing native contract. It does not skip or contact systemd.
Mock fixtures cover the prior checks plus owned closure, unrelated-read exclusion, live actors, escaped actors, populated descendants, stale sockets, observer mounts, detached netns identity, and PID reuse.
These changed tests have not run. Historical mock passes qualify only their frozen historical source.

After a separate exact execution-scope decision, the proposed sole daemon-only command is the following.
No command in this document authorizes its execution now.

```sh
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/zack DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 hack/goal330-verify-runtime/daemon_bootstrap.py
```

Use three distinct future evidence lanes without reusing an uncertain attempt.

1. Run mocked refusal checks on owned temporary files. Require no unit mutation after an existing pending receipt, changed invocation, or denied read.
2. Run the single normal native attempt. Require zero images/containers, native placement, actual socket/store identities, and complete positive teardown.
3. Plan owner loss against the same exact finite identity in a separately inspected source revision or reconciled attempt. Require native daemon expiry, retained pending/failure evidence, and a root recovery gate before any further heavy grant.

Do not run lane three by blindly starting this fixed nonce again.
Do not invent a successful owner-loss or cleanup result from the prepared source.

## Require positive closure

On the normal path, stop the exact Info and daemon invocations with exact successful jobs.
Require the aggregate cgroup empty or absent, every observed PID/start time gone, and the recorded socket paths absent.
Require inactive/dead or exact native NoSuchUnit, MainPID zero when retained, and no exact queued job.
Bind closure to the recorded boot, unit invocations, canonical cgroup, observed PID/start times, and detached-netns identity.
Compare the exact observer mount table before and after and refuse private-path or detached-netns exports.
Require no observed private namespace reference in the keeper's own fd-link metadata.
Compare selected host security, forwarding, subordinate-ID, daemon-config, service-file, and host TCP-listener state.
Only then stop the exact slice and record its stop job and final empty-parent proof.
The source inventories retained private files and deletes none.

Record `owned_reference_closure` with the no-external-acquisition assumption and `outside_holders=unmeasured`.
This is owned actor/reference closure under the native contracts. It is not global namespace closure.
It cannot exclude an outside holder of any UID, an intentional cgroup escape, or namespace references transferred outside the owned set.
The native source/placement contract is part of the proof, as root's stated operational scope requires.
Any observed holder, denial, residual socket, mount, populated cgroup, or changed host state fails closure.
A stale socket remains recorded for root reconciliation. No unlink, prune, pattern kill, recursive removal, or sudo fallback follows.
After all closure checks, root must independently attest exact native closure and actual flock release in the distinct root companion.
The helper's raw `.closed.json`, a free lock, or an absent API does not authorize another heavy allocation.

No source import, Python test, Go operation, native unit operation, private runtime path, Docker API, daemon, image, container, or actual receipt was created during preparation.
No compatibility, isolation, full `make verify`, or product review result is claimed.
