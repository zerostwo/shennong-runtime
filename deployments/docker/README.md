# Rootless executor deployment

This profile deliberately uses two Docker daemons:

1. the control-plane daemon runs Shennong OS, DB, and the Runtime Daemon;
2. a dedicated rootless daemon runs only untrusted Jobs, scanners, and IDE sessions.

Never point `SHENNONG_ROOTLESS_DOCKER_SOCKET` at `/var/run/docker.sock`. Even a
rootless socket must not belong to the daemon that runs OS or DB, because its
holder can administer every container and volume owned by that daemon.

## Prerequisites

- a dedicated Linux user with rootless Docker and cgroup v2/systemd delegation;
- a private OS/DB control bridge with a dedicated host-side gateway address;
- digest-pinned daemon, worker, and IDE images;
- an Ed25519 verification public key issued by Shennong OS;
- root access to install the narrow systemd/nftables policy reconciler; Runtime
  itself remains unprivileged and never receives network-administration caps.

Bootstrap only the executor networks:

```bash
DOCKER_HOST=unix:///run/user/1001/docker.sock \
  bash scripts/bootstrap-rootless-executor.sh
```

Review the egress policy and install its root-owned recovery guard. The guard
watches RootlessKit's `child_pid`, waits for both exact bridges, installs the
policy in that namespace, verifies the namespace did not race, and atomically
publishes `/run/shennong-runtime-egress/policy-<uid>.ready`:

```bash
SHENNONG_EXECUTOR_UID=1001 \
SHENNONG_RUNTIME_PROXY_V4=10.252.0.1/32 \
  sudo --preserve-env=SHENNONG_EXECUTOR_UID,SHENNONG_RUNTIME_PROXY_V4 \
  bash scripts/install-egress-policy-guard.sh

systemctl status shennong-runtime-egress-policy@1001.path
systemctl status shennong-runtime-egress-policy@1001.service
```

`child_pid` is written by RootlessKit in the state directory configured by the
provided user systemd unit. Do not guess the namespace PID. The root path unit
reconciles every creation/change of that file and the oneshot independently
checks its PID and network-namespace inode before and after installation. It
removes the prior attestation before waiting, so all failure paths are closed.
The proxy source is an exact `/32`; broad CIDRs are rejected. Policy replacement
is one nftables transaction, so a parse/apply failure retains the previous table
in a live namespace but still withholds the new attestation.

Verify the policy against a live Runtime health endpoint on the private
control bridge. `SHENNONG_RUNTIME_CONTROL_URL` must be reachable from the host
before this command; the test passes only when Jobs cannot reach private or
metadata addresses, IDEs cannot reach Runtime control, and the host can still
reach an IDE through its loopback-only port:

```bash
DOCKER_HOST=unix:///run/user/1001/docker.sock \
SHENNONG_EGRESS_TEST_IMAGE=python@sha256:<digest> \
SHENNONG_RUNTIME_CONTROL_URL=http://172.30.0.1:7000/v1/health \
  bash scripts/verify-egress-policy.sh
```

Then supply all required Compose variables and start the daemon:

```bash
export SHENNONG_ROOTLESSKIT_STATE_DIR=/run/user/1001/shennong-runtime-rootlesskit
export SHENNONG_EGRESS_POLICY_STATE_DIR=/run/shennong-runtime-egress
export SHENNONG_RUNTIME_PROXY_V4=10.252.0.1/32
docker compose -f deployments/docker/compose.rootless.yaml config
docker compose -f deployments/docker/compose.rootless.yaml up -d
```

Ed25519 verification is the V1 production default and mounts only a public key.
The `compose.hs256.yaml` override is retained solely for rollback compatibility
with an existing legacy deployment; it is outside the V1 acceptance profile.
When that explicit override is used, the shared secret is mounted through
Compose secrets and is never placed in an environment variable.

The Compose file uses host networking for the trusted Runtime Daemon but does
not publish a Compose port. `SHENNONG_RUNTIME_LISTEN` must be the exact private
control-bridge gateway (or loopback); the daemon rejects `0.0.0.0` and public
addresses. OS reaches that private address from its control network.
`SHENNONG_RUNTIME_INSTANCE_ID` must be stable for this worker across restarts
and unique among Runtime instances using the same rootless daemon; all managed
containers are labeled with it before instance-scoped orphan reconciliation.
The Compose profile read-only mounts the RootlessKit state and root-owned
attestation directories. Runtime rejects startup, `/v1/health`, and every new
Job/Session launch whenever the attestation is missing, mutable, stale, belongs
to another UID, has different bridge/proxy settings, or races a `child_pid`
change. Cleanup/reconciliation remains available so policy failure cannot strand
existing executor objects.

IDE containers publish only their authenticated gateway on a random
`127.0.0.1` port; RStudio/Jupyter listen on container loopback. Runtime consumes
that target and exposes
`/v1/sessions/{id}/proxy/*` with JWT and ownership checks. Session responses
return only `proxy_path`; OS cannot see or dial the loopback target directly.

Runtime retains the per-Session raw gateway secret in its journal; Docker
inspect exposes only a SHA-256 digest, which cannot be replayed as the gateway
header. The OS proxy owns browser authentication and Origin/CSRF validation, then
forwards HTTP/WebSocket traffic to Runtime's proxy path with a short-lived
`runtime:sessions:proxy` JWT. Runtime enforces ownership, activity-based idle
expiry, live-stream revocation, and absolute TTL.
Expose IDE traffic on a separate, preferably per-Session, browser origin and
ensure OS auth cookies are host-only. Set `SHENNONG_OS_AUTH_COOKIE_NAMES` to the
exact comma-separated OS cookie names so Runtime can strip them again. A
same-origin path below the OS application is not supported for untrusted IDE
content.
