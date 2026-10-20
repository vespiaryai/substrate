# Prepare the disposable Docker compatibility diagnostic

This is an unrun source proposal against public base `4e0fdbaf21db818706fdf67b3e56201d34dfd433`.
The diagnostic source is prepared. A complete executable launcher remains blocked by the ownership evidence described below.
Do not execute the command proposal as a launch script.
Root owns exact later build, acquisition, daemon, diagnostic, full-verifier, and review decisions.

## Inspect the intended usage

After the missing launcher work and root's execution-scope inspection, use the diagnostic inside an owned transient service.
The future private binary accepts the following arguments.

```text
diagnostic -endpoint unix:///run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/docker.sock -daemon-id <ID read from that owned daemon> -case postgres
diagnostic -endpoint unix:///run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/docker.sock -daemon-id <same owned ID> -case guard -pause-at native-info
```

The daemon ID cannot be resolved without a later runtime grant. It is a required observed input, never a guessed value.
The proposal nonce was read once from `/dev/urandom`. No directory, socket, unit, or runtime receipt with that nonce was created.
Reject any existing identity or previously used receipt before a later attempt. Regenerate the entire command proposal if that check fails.
Never replay this proposal as recovery. Reconcile the original failed receipt first.

## Finish the source blockers before a launch

- [ ] Supply one small controller that starts inside the slice from birth and performs the listed inventory and cleanup.
- [ ] Trace the installed containerd and native runtime paths that request systemd scope placement. Require the slice and daemon cgroup-parent contracts plus fork inheritance for ordinary children.
- [ ] Capture exact jobs, InvocationIDs, boot ID, PID start times, cgroups, socket inodes, listener owners, namespace mounts, and runtime object IDs.
- [ ] Reconcile uncertain systemd replies and stop every exact owned sibling container scope. Stopping the daemon service alone is insufficient.
- [ ] Keep an outside-parent lock holder alive until positive cleanup closure. On uncertainty retain the original failure receipt and lock, and block replacement work.
- [ ] Specify recovery if the lock holder itself dies. An automatically released flock alone does not prohibit a new owner from overlapping residual work.
- [ ] Prepare an owned alternative endpoint inside the same aggregate parent, with an actual zero-create oracle. No shared daemon canary is allowed.
- [ ] Prepare a source-byte manifest and a refusal oracle on an owned fixture. A before/after hash alone cannot detect a change and restoration during a command.

These are missing source and command steps, not successful runtime checks. No unsupported helper or self-reported closure fills them.
The preparation therefore does not deliver an executable safe launcher or authorize runtime work.

Root's follow-up `msg_2a7a89fe1c2a` accepts a scoped operational argument rather than a universal history of every possible PID.
Use source-backed fork inheritance, exact native placement APIs, actual pre-start ancestor controls, all observed parents, event/object inventory, resource-failure controls, and positive final empty-parent proof together.
Do not add a global tracer or supervisor. Incomplete universal PID history is a limit, not a source blocker by itself.
Any source-backed escape or observed actor outside the parent still blocks. No actual escape has been established in this preparation.
The remaining concrete blocker is the absent controller and exact cleanup/recovery implementation, including the audit of native scope-placement calls.

## Keep the native call sequence

`hack/goal330-verify-runtime/main.go` uses the existing vendored testcontainers and PostgreSQL modules at v0.44.0 and Moby client v0.5.1.
Its invocation record contains the literal endpoint, expected daemon ID, case, and one optional checkpoint.
The native objects retain their library types and owners. The source adds no provider injection or protocol adapter.

1. Validate the private endpoint and fixed runtime environment. Require an empty private `.testcontainers.properties`.
2. Create a native Moby client with explicit `WithHost`, call `Info`, compare daemon ID, and close the client.
3. Construct the first no-options `NewDockerProvider`. Require literal `Client().DaemonHost()` equality and successful wrapper `Info` with the same ID.
4. Construct a second no-options provider after successful wrapper caching. Require the same literal endpoint. Close both providers before returning from the guard.
5. For the PostgreSQL case, recheck configuration, inspect the pinned local images, and require an empty private container inventory.
6. Call native `postgres.Run` once with `postgres:18-alpine` and the module's native `BasicWaitStrategies`. No custom container, security, parent, or reaper modifier exists.
7. Record PostgreSQL inspect data. Require exactly PostgreSQL and one active, unprivileged, same-session Ryuk at its unchanged image tag. Record Ryuk inspect data.
8. Use native mapped `ConnectionString`, connect with pgx, ping, and close the connection. Terminate PostgreSQL on ordinary return, including an error after a partial return.

An error or panic before guard completion cannot reach the sole `postgres.Run` call. A partial creation that panics or loses the API still needs independent owned cleanup.
The context timeout is 40 seconds, but provider constructors use `context.Background` internally. Only a finite service lifetime and positive process exit bound those constructors.
The source does not claim to prove Ryuk deletion, process placement, seccomp, loopback listeners, or namespace cleanup.
The controller must check both published bindings and actual IPv4/IPv6 listeners before releasing `postgres-ping`.

The checkpoint writes a named line to stdout and reads exactly `continue` plus newline from stdin.
Use a run-private FIFO opened by the controller before starting the process. EOF or any other input fails.
Never send continuation until the matching root-owned evidence check is complete.

## Reserve the finite phases

Use two CPUs, 4 GiB, zero swap, and 512 tasks for the entire aggregate, including controller, tools, daemons, helpers, and containers.
This is part of the program's six-CPU/eight-GiB allocation, not an additional allocation.
Hold `/tmp/vespiary-heavy-validation.lock` outside the slice from first source preparation through positive postflight closure.
Reserve at most 180 seconds for cold source/build work. Preserve its failure receipt if that ceiling is insufficient.
Reserve one later 600-second runtime window. Bound daemon and acquisition to the first 300 seconds, five diagnostic processes together to 240 seconds, and teardown to the final 60 seconds.
Stop creation by 180 seconds into the diagnostic phase. Do not extend or retry a failed phase automatically.
Relative `RuntimeMaxSec` values do not enforce a common absolute deadline. The missing controller must compute remaining times from one monotonic deadline.

## Inspect the exact launcher proposal

Read [launcher.md](launcher.md) and `hack/goal330-verify-runtime/systemd_job.py` before any execution decision.
The Python helper uses the already installed dbus-python and GLib. It has no command entrypoint and was neither imported nor executed.
It filters `JobRemoved` by exact unit name, subscribes before mutation, and requires the exact returned job path with result `done`.
Use a dedicated connection and `timeout=5` on every mutation. A timeout is unknown state, never permission to retry under another nonce.
The fragment closes that dedicated connection on return. It does not share or retain a bus connection between jobs.
The helper is an untested fragment, not the missing controller or an accepted launcher.

## Keep source and caches private

Prepare a new independent clone from `git@github.com:vespiaryai/substrate.git` only, with required ancestry and release tags.
Do not use upstream main, local alternates, borrowed hooks, credentials, worktree metadata, or a shared cache.
Freeze the source, tags, vendor bytes, scripts, configuration, tests, and build inputs before any future command.
The product certificate candidate `e36ff188` stays separate and untouched.
Use the already installed `/home/zack/.local/share/mise/installs/go/1.27.2/bin/go` with `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`, and `-mod=vendor`.
Set fresh private GOCACHE, GOMODCACHE, TMPDIR, HOME, and binary output paths beneath the proposal's private directory.
Compile only within the bounded parent and heavy slot. No Go import, build, test, tool download, or cache population ran during this preparation.

## Preserve the image metadata

Four anonymous `/usr/bin/skopeo inspect --raw` calls used explicit docker.io references, `--no-creds`, `--authfile /dev/null`, and zero retries.
Each used an outer 30-second timeout, a 25-second command timeout, and a three-second kill grace. All four returned zero with empty stderr.
Only indexes and platform manifests were fetched. No image layer, image configuration blob, credential, pull, Docker API, or image store was used.
The raw response hashes match both selected platform manifest digests.

| Native tag | linux/amd64 manifest | Config digest declared by that manifest |
| --- | --- | --- |
| `postgres:18-alpine` | `sha256:d8703cd7fba306b9fec9268ecedfa8a966846c053036a60e3635791957eb2f66` | `sha256:c293117fcecda7344b5480222e813b9f673d7abd69b1dd95eff239b768b04f59` |
| `testcontainers/ryuk:0.14.0` | `sha256:f0456560ea5b4acdbed0da0efc33b5f9dd6bc1e59f2337106826dcb5b0b0e981` | `sha256:9a5f93e8f9300530b91866bcf41c0b8a5d72f0e5a7b4365167a48df9816cd36e` |

The index declares linux/amd64. The config blobs were not fetched, so their contents remain unverified until bounded acquisition.
Record downloaded bytes and verified image IDs in the later receipt, then tag locally with the unchanged fixture names.
No mutable-tag force pull, registry mirror, auth borrowing, shared-store seed, fallback driver, or second runtime is permitted.

## Run at most five fresh diagnostic processes later

1. Stop the owned endpoint before a `-case guard` process starts. Require failure and zero Create events on both owned endpoints.
2. Use `-case guard -pause-at native-info`. Stop the expected endpoint after the native Info line, then continue. Any fallback must fail literal equality before Create.
3. Use `-case postgres -pause-at guarded`. Stop the expected endpoint after priming both providers, then continue. Require failure and zero alternate Creates.
4. Use `-case postgres -pause-at postgres-ping`. Inventory and prove both actual loopback publications before continuation. Require mapped PostgreSQL ping and exact cleanup.
5. Use the same PostgreSQL checkpoint in a fresh process. Cancel that exact diagnostic service while daemon and Ryuk remain alive. Require native reaping within the shared deadline.

Do not reset global caches or patch a client. The third process must fail before creating when its explicit image inspection cannot reach the daemon.
The second process tests the between-probe outage. The first tests refusal before discovery. Further cache states need a separately revised scope.
The alternative endpoint must have its own private state and finite lifetime below this same parent. Its preparation is an open launcher blocker.
No creation or cancellation case ran. No claimed zero-create or cleanup result exists.

## Keep mandatory verification and review order

Root first inspects these actual diagnostic bytes and the eventual finite launcher. That is execution-scope inspection.
After independent compatibility proof, root owns the shared product guard, all four fixture entrances, strict authz errors, and fresh-process oracles.
Prove required preconditions fail in CI rather than skip. Include the certificate fixture's separate container.
Pass stable-source focused tests and full bounded `make verify` before requesting product code review, as external AGENTS requires.
Keep every original verifier, release-tag migration check, race test, and Weaver gate. No result here supplies those passes.

## Record the workflow and current limits

The required Poteto, how, architect, bug-fix, type-system, control-cli, deslop, no-comments, technical-writing, unslop, and official skill-creator leaves were read.
No installed lifetime or separate split-PR leaf was found. The supplied lifetime contract and Poteto Opening a PR workflow remain authoritative.
The already judged A/B designs supply Ground and Sketch. Root's synthesis supplies Agree. This worker owns only the disposable source preparation.
Nested delegation, runtime reproduction, CLI driving, tests, and model calls were forbidden, so those skill steps did not run.
Unavailable Cursor Task types, Comment Sicko, and Cursor create-skill did not run. The installed official skill-creator supplied agent-facing prose guidance.
The split-PR workflow remains with root. No PR or product code review is requested.

The throughput checkpoint follows the Feature playbook.

- Blocking first steps were complete source/design reads, exact installed API inspection, and metadata identity resolution.
- Independent workstreams are n/a because nested workers are forbidden and one owner controls this small disposable unit.
- Shared mutable state stays untouched. All proposed state belongs to one fresh nonce, with one future receipt writer.
- Smallest safe decomposition is one diagnostic, one native job fragment, and a command proposal. The missing cleanup owner stays a blocker.

Model the Domain selected one immutable invocation record. Type System Discipline kept the SDK's native client and inspect types.
Laziness Protocol rejected a runtime framework. Prove It Works keeps every runtime claim unproved.
The only verification allowed now is direct source inspection, owned-file gofmt, whitespace checks, and hashes.
The prepared Go tests reject shared endpoints and conflicting runtime settings. They are unrun and do not establish native outage safety.
