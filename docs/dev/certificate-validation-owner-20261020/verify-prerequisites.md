# Full verification prerequisites

This is a source inspection plan. No Docker probe, tool installation, daemon change, full test, or verification script ran during this inventory.
The focused config, cmd, steps, and demos tests use in-process HTTP fixtures and owned temporary files and scripts.
They need no Docker daemon or real cluster and fit the granted parent user-unit controls.

## Separate the full target's processes

`Makefile:143` runs `go test -race ./...`; `Makefile:178` then runs all fourteen `hack/verify/*.sh` scripts.
The later reservation has a maximum of 1800 seconds and requires a committed clean tracked candidate.
The unchanged source guard covers tracked and untracked nonignored application, test, and configuration bytes.
Receipts and command output stay outside source until completion. Changed inputs invalidate the result.

| Owner | Observed external work | Bounds and cleanup in current source |
| --- | --- | --- |
| `cmd/ateapi/internal/store/atepg/main_test.go:66` | Shared `postgres:18-alpine` container. | No CPU, memory, swap, or cgroup-parent options. `TestMain` closes the pool and terminates the container, making termination failure affect success. |
| `cmd/ateapi/internal/store/atepg/cert_auth_test.go:91` | Additional certificate-auth PostgreSQL container after `requirePool`. | No resource limits. `testcontainers.CleanupContainer` owns cleanup. The shared container remains live concurrently. |
| `cmd/ateapi/internal/store/storetest/storetest.go:170` | One shared PostgreSQL container per importing test binary, including control API, worker service, HTTP API, and actor service tests. | No resource limits. `RunTests` or each package's `TestMain` must call `Shutdown`; its termination failure only logs. |
| `cmd/ateapi/internal/authz/authz_test.go:70` | PostgreSQL per helper call. | No resource limits. Cleanup terminates the container and closes the pool; termination errors are ignored. |
| Vendored testcontainers reaper | Docker-managed Ryuk cleanup process. | Separate from the Go parent's cgroup. Current config exposes cleanup and endpoint options, not general container CPU, memory, or swap limits. Do not disable or privilege it. |
| `internal/testenv/testenv.go:49` | Local kube-apiserver and etcd children. `setup-envtest` may download installed 1.36.x assets under a cross-process setup lock. | These children inherit the user unit's limits. `env.Stop` performs cleanup; stop errors only log. `-short` would skip packages and is excluded from this plan. |
| `hack/verify/metrics.sh` and vendored `verify-shellcheck.sh` | Pinned Weaver 0.25.1 and ShellCheck 0.9.0 Docker fallback images. | Their `docker run --rm` commands have no CPU, memory, or swap limits. Supported exact local binaries avoid this Docker path and inherit the user unit. |
| `hack/third_party/kubernetes/verify-generated.sh` | Scratch Git worktree at committed HEAD, update scripts, tool builds, code generation. | It refuses dirty tracked source and removes its own scratch worktree on EXIT. Child processes inherit the unit. An interrupted unit still needs explicit exact-worktree postflight. |

The unchanged PostgreSQL callers pass no `WithHostConfigModifier`, `Memory`, `NanoCPUs`, `CPUQuota`, `MemorySwap`, or `CgroupParent` option.
A two-CPU/four-GiB/zero-swap Go unit does not bound containers started by an external dockerd.
Serial package execution can reduce concurrent containers but does not supply a resource ceiling or zero-swap proof.
There is no existing per-fixture resource setting in these call sites that this owner can select.
The full race suite therefore remains gated on a concrete reviewed Docker resource and cleanup plan within the overall six-CPU/eight-GiB/zero-swap envelope.
Do not start or modify a daemon, change security or socket access, add a transparent Docker wrapper, alter fixtures outside this repair, or waive the target to pass it.

## Preserve required environment failures

`dockerenv.Required()` fails missing PostgreSQL prerequisites when `CI=true` or `REQUIRE_DOCKER=true`.
`atepg` and `storetest` use that predicate. Local default skips cannot prove these packages ran.
The separate authz helper currently skips unavailable Docker or container startup even in CI.
That is an inherited limitation to report, not permission to silently count skipped tests as acceptance or expand this source repair.
Envtest asset or startup failure exits 1 through `testenv.fatal`.
Existing root-only tests intentionally require their separate privileged test route; this source repair grants no root execution.
The ordinary full target leaves e2e suites inactive through their existing `--e2e` opt-in. It supplies no real-cluster qualification.
The GCS emulator tests likewise require their existing emulator setting; no emulator is to be started as part of this certificate repair without a separate concrete scope.

The full target also includes the existing installer shim tests.
Their translation helper replaces `go` with a temporary logging stub and a fixed environment.
The help assertion reads shell usage. These tests do not authorize a live installer, actual bootstrap, profile selection, or cluster command.

## Inventory tool work before its reservation

Read-only PATH inventory found Docker, Podman, Python 3, and curl, and no ShellCheck, Weaver, or protoc.
No installed version or daemon health is inferred from executable presence.
`hack/protoc.sh` pins protoc 25.3 and checks a platform SHA256 before extraction into ignored `bin/protoc-install`.
`hack/run-tool.sh` resolves tools through their checked-in Go tool modules, including code generators, protobuf generators, linters, licenses, and setup-envtest.
Python verification creates local virtual environments, syncs checked-in requirement files, and may install `pip-licenses`.
Every necessary install, image pull, build, and execution belongs to the one heavy slot and needs recorded provenance and cleanup.
No module, dependency version, checksum, manifest, or source profile change is allowed.

Before granting the full target, root must reconcile actual Docker bounds, termination and orphan postflight, tool needs, and any reviewed scope needed for local test containers.
If those prerequisites cannot be supplied within current authority, retain the exact pending gate and the committed source unit.
Focused success will not replace mandatory `make verify`.
