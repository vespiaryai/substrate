# Inspect the bounded launcher command proposal

This reference is incomplete and unrun. It is not an executable launcher or an execution grant.
The missing controller, scope-placement audit, retained lock recovery, and positive cleanup are blockers in [plan.md](plan.md).
The commands below fix the supported parts so root can inspect actual arguments rather than approve an abstract scope.
No runtime paths or units below exist because of this task.

## Exact proposed identities

```text
Nonce = b7a6306f20fabfaab02a29eaecf04531
P = /home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531
R = /run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531
S = vesverifyb7a6306f20fabfaab02a29eaecf04531.slice
Controller = vesverifyb7a6306f20fabfaab02a29eaecf04531-controller.service
Daemon = vesverifyb7a6306f20fabfaab02a29eaecf04531-daemon.service
Compile = vesverifyb7a6306f20fabfaab02a29eaecf04531-compile.service
Acquisition = vesverifyb7a6306f20fabfaab02a29eaecf04531-acquisition.service
Diagnostic units = vesverifyb7a6306f20fabfaab02a29eaecf04531-case1.service through case5.service
Bus = unix:path=/run/user/1000/bus
URI = unix:///run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/docker.sock
```

Before mutation, the outside lock keeper checks absence of all exact paths, symlinks, unit names, and pending jobs.
It holds a nonblocking flock on `/tmp/vespiary-heavy-validation.lock` through positive cleanup. It performs no build, image, or diagnostic work.
The tiny slice/service bootstrap belongs to this outside bookkeeping owner. The controller's ExecStart begins inside S.
The missing controller cannot inherit a process that ran outside S and then migrate it inward.
Lock-file existence is not ownership, and a failed receipt must remain available even when flock is released by a crash.
No complete crash-safe keeper invocation is supplied yet.
Ordinary fork/exec children inherit the parent's cgroup. The installed launcher directly execs RootlessKit, which then execs dockerd in private namespaces.
The native daemon's container cgroup-parent is a supported default, not evidence that every helper follows it.
Audit containerd/runtime systemd scope-placement calls separately. Combine those source contracts with observed actor parents and positive final empty-parent proof.
Root accepts that scoped operational evidence without a universal short-lived PID history. No sampling-alone proof is claimed.

## Slice job and actual limits

The following is the native dbus-python operation for `owned_job` in the proposed source fragment.
It has not run. The caller retains the exact job path, result, boot ID, and intent receipt.

```python
owned_job(bus, "vesverifyb7a6306f20fabfaab02a29eaecf04531.slice", lambda manager:
    manager.StartTransientUnit(
        "vesverifyb7a6306f20fabfaab02a29eaecf04531.slice", "fail",
        dbus.Array([
            ("Description", dbus.String("goal330 b7a6306f20fabfaab02a29eaecf04531")),
            ("CPUQuotaPerSecUSec", dbus.UInt64(2000000)),
            ("MemoryMax", dbus.UInt64(4294967296)),
            ("MemorySwapMax", dbus.UInt64(0)),
            ("TasksMax", dbus.UInt64(512)),
        ], signature="(sv)"),
        dbus.Array([], signature="(sa(sv))"), timeout=5))
```

Use GetUnit and Properties.GetAll on that unit's returned object path. Require Transient, active state, exact description, and captured InvocationID and ControlGroup.
Resolve that exact ControlGroup below `/sys/fs/cgroup` without path escape.
Read `cpu.max`, `memory.max`, `memory.swap.max`, `pids.max`, `cgroup.controllers`, and `cgroup.subtree_control` at that group and every applicable ancestor.
Require available cpu, memory, and pids controllers and actual effective bounds no weaker than the allocation.
The root cgroup has no parent limit files on some controllers. Record that fact rather than fabricating values.
Do this before the controller starts heavy children and again before daemon startup. A systemd property alone does not prove actual limits.

Every service uses native StartTransientUnit with mode `fail`, Type `exec`, Slice S, Restart `no`, KillMode `control-group`, and an explicit finite RuntimeMaxUSec.
Only the daemon has Delegate `true`. All other services have Delegate `false`.
The controller remains active until postflight, preserving the slice while daemon and container sibling scopes exist.
Use the exact filtered job helper for service starts and stops. A returned object path alone proves enqueue, not completion.
No broad `busctl monitor`, stock service, enablement, linger change, cgroup write, PID move, or new user is part of the proposal.

## Private directory and daemon bytes

The future bounded controller creates P and R with exclusive absence checks, umask 077, UID 1000 ownership, and mode 0700.
It creates home, config, xdgdata, cache, tmp, bin, src, go-build, go-mod, and docker-config below P, plus `R/xdg`.
It creates empty `P/home/.testcontainers.properties` and private `P/docker-config/config.json` containing `{}`.
It does not precreate `R/rootlesskit` or `R/no-standalone-containerd`.
It rejects `R/xdg/containerd/containerd.sock`, every daemon socket collision, and symlinks in the private ancestry.
These are planned files, not files written by this source task.

The exact future `P/daemon.json` is as follows.

```json
{"data-root":"/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/data","exec-root":"/run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/exec","pidfile":"/run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/docker.pid","hosts":["unix:///run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/docker.sock"],"exec-opts":["native.cgroupdriver=systemd"],"cgroup-parent":"vesverifyb7a6306f20fabfaab02a29eaecf04531.slice","default-cgroupns-mode":"private","ip":"127.0.0.1","default-network-opts":{"bridge":{"com.docker.network.bridge.host_binding_ipv4":"127.0.0.1"}},"features":{"containerd-snapshotter":true,"embedded-containerd":false},"max-concurrent-downloads":1,"max-download-attempts":1,"shutdown-timeout":10}
```

The proposed daemon ExecStart argv is the following command, inside its owned delegated service.
The CLI spelling shows the same Type, Slice, lifetime, and kill settings for inspection. The missing controller must use exact native jobs and a shared absolute deadline.

```sh
systemd-run --user --unit=vesverifyb7a6306f20fabfaab02a29eaecf04531-daemon.service --slice=vesverifyb7a6306f20fabfaab02a29eaecf04531.slice --service-type=exec -p Delegate=yes -p KillMode=control-group -p Restart=no -p RuntimeMaxSec=600 -p TimeoutStopSec=15 /usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/home XDG_CONFIG_HOME=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/config XDG_DATA_HOME=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/xdgdata XDG_CACHE_HOME=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/cache XDG_RUNTIME_DIR=/run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/xdg TMPDIR=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/tmp DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR=/run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/rootlesskit CONTAINERD_ROOTLESS_ROOTLESSKIT_STATE_DIR=/run/user/1000/vesverifyb7a6306f20fabfaab02a29eaecf04531/no-standalone-containerd DOCKERD_ROOTLESS_ROOTLESSKIT_NET=pasta DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=implicit DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=true DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true /usr/bin/dockerd-rootless.sh --config-file=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/daemon.json --group=0
```

Preserve the real user bus despite private XDG_RUNTIME_DIR. Otherwise managed-containerd discovery can adopt the shared runtime socket.
Require `/usr/bin/containerd` and installed Docker 29.9.0 build a5b58c9. Never use `--containerd`, DOCKER_CONTAINERD_ROOT, an embedded fallback, or a legacy storage-driver fallback.
The expected managed containerd identities are fixed below.

```text
root = P/data/containerd/daemon
state = R/exec/containerd/daemon
config = R/exec/containerd/containerd.toml
pidfile = R/exec/containerd/containerd.pid
grpc = R/exec/containerd/containerd.sock
debug = R/exec/containerd/containerd-debug.sock
argv = /usr/bin/containerd --config R/exec/containerd/containerd.toml
```

Record actual generated bytes, argv, PID start time, mount namespace, root/state/socket paths, and native snapshotter before any image acquisition.
The exact-prerequisites report traced these paths to Moby build commit a5b58c94d334674eae3a3207d4f05417643a90d0.
The command proposal does not prove installed behavior. Any mismatch or access denial stops acceptance.

Keep host SELinux Enforcing, default seccomp, private cgroup namespaces, native mappings, normal Ryuk, and the plain socket bind.
Record process contexts, socket and parent labels, UID/GID maps, namespace identities, actual seccomp, and capabilities.
The installed launcher labels its copied-up child `/run` and writes forwarding only in its private network namespace. Verify the host originals stay unchanged later.
No `selinux-enabled` experiment, disable flag, unconfined override, privileged Ryuk, relabel, policy change, or denial bypass is permitted.
Pasta/implicit is installed and documented experimental. Compatibility success would provide no Substrate isolation qualification.

## Cold compile and image acquisition

After an independently prepared private source clone and parent checks, the compile service's exact command is the following.
Its working directory is `P/src`, RuntimeMaxSec is 180, TimeoutStopSec is 10, and Delegate is false.

```sh
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/home GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor GOMAXPROCS=2 GOCACHE=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/go-build GOMODCACHE=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/go-mod TMPDIR=/home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/tmp /home/zack/.local/share/mise/installs/go/1.27.2/bin/go build -p=2 -trimpath -o /home/zack/.local/share/vesverifyb7a6306f20fabfaab02a29eaecf04531/bin/diagnostic ./hack/goal330-verify-runtime
```

Acquisition uses an empty private Docker config, the exact URI, TLS-verified public registries, no credentials, and the same bounded parent.
These are the only proposed image pull and tag mutations, each subject to the shared remaining deadline.

```sh
/usr/bin/docker --config "$P/docker-config" --host "$URI" pull --platform linux/amd64 docker.io/library/postgres@sha256:d8703cd7fba306b9fec9268ecedfa8a966846c053036a60e3635791957eb2f66
/usr/bin/docker --config "$P/docker-config" --host "$URI" pull --platform linux/amd64 docker.io/testcontainers/ryuk@sha256:f0456560ea5b4acdbed0da0efc33b5f9dd6bc1e59f2337106826dcb5b0b0e981
/usr/bin/docker --config "$P/docker-config" --host "$URI" image tag docker.io/library/postgres@sha256:d8703cd7fba306b9fec9268ecedfa8a966846c053036a60e3635791957eb2f66 postgres:18-alpine
/usr/bin/docker --config "$P/docker-config" --host "$URI" image tag docker.io/testcontainers/ryuk@sha256:f0456560ea5b4acdbed0da0efc33b5f9dd6bc1e59f2337106826dcb5b0b0e981 testcontainers/ryuk:0.14.0
```

P, R, S, and URI abbreviate only the literal identities above. They are not caller-selected inputs.
Image inspect must match each manifest's declared config digest, OS, architecture, and unchanged local tag before testcontainers runs.
No image bytes were fetched during this task.

## Diagnostic service environment and lifetime

Use `/usr/bin/env -i` with PATH `/usr/bin:/bin`, the private HOME, and the following exact runtime settings.
Set the private TMPDIR and XDG_RUNTIME_DIR too. Supply no other DOCKER, TESTCONTAINERS, RYUK, TLS, credential, context, or session variables.

```text
DOCKER_CONFIG=P/docker-config
DOCKER_HOST=URI
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=R/docker.sock
TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1
TESTCONTAINERS_RYUK_DISABLED=false
TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED=false
```

Each diagnostic uses RuntimeMaxSec 45 and TimeoutStopSec 5, with an earlier shared absolute deadline if needed.
Open its private stdin FIFO before ExecStart. Route stdout and stderr to owned append-only receipt files through systemd's native file properties.
The missing controller records pre-create object inventory and native Docker event histories on both owned endpoints.
It reads actual mapped ports and listener owners for PostgreSQL and Ryuk, including IPv6. Bindings must be loopback and reachable, with no LAN listener.
Neither TESTCONTAINERS_HOST_OVERRIDE nor an inspect HostIP alone proves those facts.

## Exact cleanup and retained uncertainty

Stop creation first. On cancellation, leave daemon and Ryuk alive until the native reaping observation ends.
Before any explicit Docker removal, match the daemon ID and immutable receipt. Select only exact inventoried container, network, and volume IDs.

```sh
/usr/bin/docker --config "$P/docker-config" --host "$URI" container rm --force --volumes "$recorded_container_id"
/usr/bin/docker --config "$P/docker-config" --host "$URI" network rm "$recorded_user_network_id"
/usr/bin/docker --config "$P/docker-config" --host "$URI" volume rm "$recorded_volume_name"
```

These recorded values are deliberately unresolved until creation. A name prefix or session label alone is not removal authority.
Record built-in bridge, host, and none networks separately. Their private network namespace disappears only when its exact owners exit.
Stop every inventoried sibling container scope under S with native StopUnit and exact JobRemoved completion before stopping the daemon.
Stop daemon, acquisition, compile, and diagnostic services by exact unit and captured InvocationID. Require empty cgroups and positive PID/start-time exit proof.
The controller performs postflight while alive in S. The outside keeper then stops that exact controller and S with exact jobs and empty cgroup proof.
Reset only exact owned failed units after preserving failure evidence. No UnrefUnit is needed unless this owner took a reference.

Closure requires zero owned live PIDs, populated cgroups, listeners, sockets, mounts, containers, user networks, and volumes.
Capture all namespace mounts and socket/listener inode owners. A dead daemon or absent API response does not prove closure.
No prune, prefix deletion, recursive host removal, blanket kill, shared daemon change, or sudo cleanup is supplied.
Subordinate-owned storage remains retained until root separately scopes supported cleanup after all users and mounts are positively absent.
On a lost reply, deadline, denial, source change, unknown object, or failed cleanup, preserve the original failed receipt and prohibit a replacement run.
The missing keeper/controller must enforce that prohibition. This proposal alone does not.
