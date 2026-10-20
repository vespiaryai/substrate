# Qualify the daemon-only mocks after a separate root grant

This is a finite procedure proposed for inspection, not an executable wrapper or an execution grant.
The source baseline is `457724307aac9495fc6ece580c47f92fdd43f3ae` on `vespiary-ai/goal330-daemon-only-bootstrap`.
All four Python files remain unrun and unchanged from that commit.
Root must first accept the dropin attempt's positive closure and actual heavy-lock release.
Root then grants this exact mock scope separately. No daemon attempt follows automatically.

## Bind the frozen inputs

1. Use this repository root as the command's working directory.
2. Check `daemon-only.sha256`, `daemon-only-native.sha256`, and `daemon-only-mock-native.sha256` with `sha256sum -c`.
3. Use the existing guard at `/home/zack/orca/workspaces/vespiary-continuation/goal330-postgres-close-baseline/docs/wayfinder/effect-evidence/postgres-close-baseline-20261020/source-guard.py` unchanged.
4. Require its SHA-256 to be `f98fc81cd69683177d44492150f68eec36bef531fe496a5bcd5cdc90979a9296` before and after execution.
5. Freeze the actual proposal, manifests, all tracked and untracked nonignored repository inputs, and every later approved command or oracle file.
6. Exclusively create `/tmp/goal330-daemon-mock-ctx-0e9c6c88257c` only after the later grant. Refuse an existing directory. Keep raw output and guard maps there.

The canonical guard enumerates `git ls-files --cached --others --exclude-standard` before and after its child.
Its historical exclusion is `docs/wayfinder/effect-evidence/pilot-helm-fixture-20261020/`. This attempt uses no input under that prefix.
Do not modify the guard or use the excluded prefix to hide an oracle.
The guard does not cover ignored files or installed native files. Compare the explicit native manifests before and after each phase too.
The mock-native manifest identifies installed Python, command tools, dbus and gi source, and their Python extension modules.
It does not attest every shared library or Python standard-library file.
Root must inspect and freeze any additional actual wrapper or import dependency before granting its execution.

## Hold the lock outside one finite native validation unit

1. Let an outside parent acquire `/tmp/vespiary-heavy-validation.lock` nonblocking with an exclusive flock.
2. Record the parent's boot, PID, start ticks, cgroup, lock device and inode, and exact command bytes.
3. Close the lock descriptor in the launch client, unit, guard, tests, and closure probes. Record that none inherited it.
4. Bind the exact validation name `goal330-daemon-mock-ctx-0e9c6c88257c.service` before launch.
5. Read the actual `app.slice` ControlGroup. Require an absolute canonical path and derive the exact expected child cgroup from it and the unit name.
6. Before launch, require native `LoadState=not-found`, `ActiveState=inactive`, `SubState=dead`, `MainPID=0`, no exact queued job, and positive absence of that cgroup.
7. Start only this transient validation unit under `app.slice`. Use CPUQuota=200%, MemoryMax=2G, MemorySwapMax=0, TasksMax=128, RuntimeMaxSec=60, RuntimeRandomizedExtraSec=0, TimeoutStopSec=5, KillMode=control-group, SendSIGKILL=yes, Restart=no, LimitAS=2147483648, and LimitCPU=50.
8. Bound the waiting launch client to 70 seconds with TERM followed by KILL after two seconds. Use `systemd-run --user --wait --pipe --collect` and the exact working directory.
9. Inside the unit, record its invocation, PID/start ticks, cgroup, actual leaf and ancestor controls, and address-space limit before the tests.
10. Require two CPUs or less, memory at most 2147483648 bytes, zero swap, at most 128 tasks, and the exact expected cgroup. Refuse missing or denied controls.

Keep the parent's normal successful procedure within 90 seconds, including closure probes.
Each native property or job observation has a three-second client timeout and at most one attempt.
The 90-second budget is not permission to release an uncertain lock.
If closure is unknown, preserve failure evidence and keep the outside parent alive with its flock for root's exact recovery decision.
Do not add an automatic retry, stop loop, supervisor, generalized runner, or unrelated witness process.
Parent death releases flock. Root's durable failed-attempt scheduling gate must still refuse another allocation until exact reconciliation.
This proposal needs later concrete command-byte inspection before launch. No existing wrapper is authorized for blind reuse.

## Run only the two selected test modules

Inside the granted native unit, use an empty environment with PATH=/usr/bin:/bin, HOME=/home/zack, PYTHONDONTWRITEBYTECODE=1, and TMPDIR under its exclusive evidence directory.
Do not pass a session-bus address or Docker environment variables.
Use the unchanged canonical guard around the following exact child command from the repository root.
Use this exact outside-repository prefix for the suite's guard receipts.

```sh
/usr/bin/python3 -I -B /home/zack/orca/workspaces/vespiary-continuation/goal330-postgres-close-baseline/docs/wayfinder/effect-evidence/postgres-close-baseline-20261020/source-guard.py /tmp/goal330-daemon-mock-ctx-0e9c6c88257c/suite /bin/bash -euc '
/usr/bin/python3 -B -m unittest discover -s hack/goal330-verify-runtime -p test_daemon_bootstrap.py -v
/usr/bin/python3 -B -m unittest discover -s hack/goal330-verify-runtime -p test_systemd_job.py -v
'
```

Require all ten daemon tests and all four job-helper tests to pass without skips, plus child exit zero and guard exit zero.
Require equal actual before and after maps with no changed inputs and `stable=true`.
The tests use native Python dbus/gi imports and parse installed XML. They mock manager operations and use owned temporary filesystem fixtures.
The entrypoint-refusal test mocks the alarm, lock, owner metadata, and receipt writer before calling `daemon_only()`.
No actual daemon alarm, heavy-lock acquisition by that mocked entrypoint, runtime path, pending receipt, or systemd mutation follows from that test.
The test unit itself is the only proposed native mutation.

## Prove the unchanged guard refuses an owned fixture change

In the same finite unit, exclusively create `hack/goal330-verify-runtime/mock-qualification-ctx-0e9c6c88257c/guard-refusal.txt` before its first guard snapshot.
Refuse an existing fixture directory. Confirm Git enumerates that exact path as a nonignored untracked input.
Freeze and record the initial literal bytes `unchanged\n`. Keep fixture copies and raw maps outside the repository.
Run the unchanged guard once with prefix `/tmp/goal330-daemon-mock-ctx-0e9c6c88257c/stable` and child `/usr/bin/true`. Require exit zero with equal maps.
Run it once with prefix `/tmp/goal330-daemon-mock-ctx-0e9c6c88257c/mutated` and this exact child.

```sh
/bin/bash -euc 'printf "changed\n" > "$1"' bash hack/goal330-verify-runtime/mock-qualification-ctx-0e9c6c88257c/guard-refusal.txt
```

Require child exit zero, guard exit 97, `stable=false`, and exactly that fixture path in `changed`.
Restore the original bytes only after the guard has written the mutation's after map and receipt.
Run the guard once more with prefix `/tmp/goal330-daemon-mock-ctx-0e9c6c88257c/restored` and child `/usr/bin/true`.
Require exit zero, equal maps, and equality to the initial stable map.
Preserve all three receipts. Do not mutate application, test, native, or historical evidence bytes.
Remove no source or historical receipt as part of this procedure.
This control proves a retained change is refused. It does not detect change and restoration between the guard's two snapshots.

## Close the exact native unit before release

1. Save raw launch-client, test, guard, native unit, and exact job observations even on failure or timeout.
2. Require a parsed terminal unit state with MainPID=0, no remaining exact job, and positive absence of the bound cgroup. Permission denial is unknown.
3. For a successful attempt, require inactive/dead or collected not-found, Result=success when retained, and zero client, child, and guard exits.
4. A failed unit may close after failure, but its result remains failed. Require terminal state and the same positive job, process, and cgroup closure.
5. Record absence of the observed unit PID/start-time identity. Require the outside parent still alive, outside the unit, and its flock still held at postcheck.
6. Compare all actual source, oracle, proposal, guard, and native bytes with the frozen inputs. Preserve any mismatch as failed acceptance.
7. Only after positive closure, let the parent release flock and exit. Record its exit and a successful separate nonblocking reacquisition and release of the same lock inode.

For native jobs, accept only typed no-job `(uo)` with zero ID and `/`, or the inspected native CLI `Job=` representation.
For `list-jobs --output=json`, accept an empty zero-exit stdout/stderr pair as no jobs, or a parsed array without the exact unit.
Reject nonzero status, malformed output, duplicate or missing required properties, an exact queued job, present cgroup, active PID, or denial.
An empty API response alone proves none of the required closure predicates.

## Preserve the limits

No code has been imported, compiled, tested, or executed to qualify this proposal.
The fourteen prepared tests do not prove the bootstrap exception path's real process exit or flock release.
They do not prove daemon startup, native alarm expiry, actual cleanup, native service-property acceptance, owner loss, or Info security fields.
No Docker API, daemon, image, container, Go, install, sudo, product, certificate, vendor, or configuration change is proposed by the mock phase.
The normal daemon attempt and owner-loss reconciliation need separate root decisions after this phase.
Mandatory full `make verify`, fresh independent product review, PR publication, and integration remain later gates.
