# Security policy

Do not deploy this repository with the system Docker socket. Runtime workload
code is treated as hostile, and a Docker socket is an executor-administration
credential.

Production invariants:

- dedicated rootless daemon or dedicated worker VM;
- no OS/DB/control-plane containers on the workload daemon;
- digest-pinned worker profiles;
- OS-issued short-lived JWTs with exact workspace claims;
- root-systemd-restored nftables egress policy, current-namespace attestation,
  Runtime fail-closed launch guard, and passing behavioral verification;
- no public Runtime or IDE port;
- OS proxy authentication in front of every IDE Session;
- a separate IDE browser origin (preferably per Session), never the OS app
  origin, with host-only OS cookies, CSP/frame restrictions, and exact OS auth
  cookie names configured for Runtime's defense-in-depth filter;
- a stable `SHENNONG_RUNTIME_INSTANCE_ID` so orphan sweeps cannot cross Runtime
  instances sharing a dedicated executor daemon;
- per-Session gateway authentication in addition to loopback binding; only a
  SHA-256 digest of the 256-bit bearer secret enters the IDE container;
- supervised `max_workspace_bytes` enforcement plus a hard filesystem quota on
  the dedicated rootless Docker data root for burst/outage containment;
- OS-only Project input resolution with verified SHA-256, strict relative paths,
  a 1 MiB aggregate limit, and an unguessable per-Job staging directory;
- verified unified backup of OS PostgreSQL, headless DB data, Runtime SQLite,
  deployment metadata/secrets, and explicitly allowlisted workspaces; Runtime
  SQLite remains a recovery journal rather than a product database.

Before production acceptance, run both behavioral gates against the exact
deployed rootless daemon: `scripts/verify-egress-policy.sh` for IPv4/IPv6 egress
and inbound policy, then `scripts/verify-live-runtime.sh` for Job lifecycle,
workspace/owner isolation, Artifact integrity, and live container HostConfig.
The live gate requires an explicit private Runtime URL, dedicated `DOCKER_HOST`,
and OS Ed25519 private-key path; it refuses the system Docker socket and does not
print the generated short-lived tokens. Restart recovery is disabled unless an
operator explicitly enables it, supplies the exact restart acknowledgment, and
provides a reviewed executable hook. The gate rejects a changed rootless engine
or replaced in-flight workload after that hook returns.

Please report vulnerabilities privately to the repository owner rather than
opening a public issue with exploit details.
