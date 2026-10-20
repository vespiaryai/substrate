# Native Info output source candidate

This source candidate repairs the first attempt's rejected transient property.
It has not run, imported, compiled, or passed a syntax check.
The [original failure and recovery](first-attempt.md) remain unchanged at parent `4a1a43dfb1a63cbab016a6b128d261dab4a0f36e`.
The consumed nonce, intent and private paths must never recur.

## Native API diagnosis

Installed packages are `systemd-259.9-1.fc44.x86_64`, `python3-dbus-1.4.0-9.fc44` and `python3-gobject-3.56.3-1.fc44`.
The installed Service XML declares `StandardOutput` and `StandardError` as strings.
It does not describe transient-only file setters, so introspection alone cannot validate this request.
Official versioned source supplies the setter contract. It matches the installed upstream version, but no rebuilt Fedora source equivalence is claimed.

The [v259.9 CLI translator](https://github.com/systemd/systemd/blob/v259.9/src/shared/bus-unit-util.c#L1222-L1246) converts `StandardOutput=file:/path` into `StandardOutputFile` with string `/path`.
The [transient dispatch](https://github.com/systemd/systemd/blob/v259.9/src/core/dbus-execute.c#L2078-L2082) sends `StandardOutput` to an enum parser.
Its [parse macro](https://github.com/systemd/systemd/blob/v259.9/src/core/dbus-util.h#L146-L177) returns `InvalidArgs` for an unknown enum.
The [enum table](https://github.com/systemd/systemd/blob/v259.9/src/core/execute.c#L3055-L3071) contains `file`, not `file:/path`.
This explains the preserved literal rejection before Info execution.

The [file setters](https://github.com/systemd/systemd/blob/v259.9/src/core/dbus-execute.c#L3335-L3399) accept normalized absolute string paths and select the output mode themselves.
The candidate sends `StandardOutputFile` for `P/info.json` and `StandardErrorFile` for `P/info.stderr` in the existing `a(sv)` array.
Neither value has a `file:` prefix. Separate stderr preserves diagnostics without corrupting the JSON stream.
No shell, pipe, passed descriptor, journal reader or extra service is introduced.

## Ownership and alternatives

`StandardOutputFile` is the exact native translation of the original intended file mode.
Append and truncate setters exist, but change that mode without a need on first-use private paths.
Descriptor passing would add client acquisition and transfer lifetimes. A journal reader would add another observer and retrieval contract.
The [native executor](https://github.com/systemd/systemd/blob/v259.9/src/core/exec-invoke.c#L630-L658) opens each path during service execution and installs the standard descriptor.
The helper creates no output file or descriptor while preparing properties.
File mode does not imply exclusive creation or truncation. Safety still depends on the existing first-use private directory contract.
Outputs remain in the owned private tree as retained evidence. The candidate deletes nothing.

Info retains oneshot, RemainAfterExit, exact slice, no restart, control-group killing, ten-second start and five-second stop timeouts.
A successful owned job still precedes output parsing and exact native teardown.
Creation rejection still propagates through `owned_job`, which removes its local timer and closes its bus.
That local release does not stop the daemon or slice and never proves closure.
Execution or file-open failure must still fail the owned job. Root reconciliation remains mandatory after any failure.

## Deferred verification

New IDs are `DaemonOnlyTest.test_info_uses_native_file_properties_without_creating_files` and `DaemonOnlyTest.test_info_creation_rejection_propagates_without_output_or_job_wait`.
They check the emitted native wire properties, distinct paths, original rejected property absence, finite unit contract and creation-error propagation/local release.
The rejection is a synthetic D-Bus error, not a native API acceptance test. Existing `OwnedJobTest.test_rejects_failed_job` covers a failed returned job.
The paired offline commands remain unrun and require a separate root grant with the canonical guard and frozen before/after bytes.

```sh
/usr/bin/python3 -B -m unittest discover -s hack/goal330-verify-runtime -p test_daemon_bootstrap.py -v
/usr/bin/python3 -B -m unittest discover -s hack/goal330-verify-runtime -p test_systemd_job.py -v
```

The [candidate manifest](daemon-native-info-output.sha256) freezes current candidate inputs without rewriting historical manifests.
Native proof needs reviewed source, independent source/comment review, an explicitly fresh nonce, first-use P/R/intent paths and a separate bounded heavy grant.
No old command bundle is reusable. Root must reconcile every pending record and both closure companions before a future grant.
No daemon retry, live mutation, privilege, installer, container, Go test or full `make verify` ran here.
Full external `make verify` remains required before product Go review. Source preparation does not qualify Goal330 or authorize integration.
