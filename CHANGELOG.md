# Changelog

## Unreleased

- Recover simple-mode job and session Docker networks during health checks when
  they were removed after Runtime startup.
- Stream bounded Artifact bytes through the helper container's captured stdout
  so downloads remain available after its tmpfs is unmounted on exit.
- Inject the current Artifact reader into historical worker images so completed
  Jobs remain downloadable after the Runtime helper contract changes.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Publish one `zerostwo/shennong-runtime` image that can run the daemon, batch
  jobs, RStudio, and JupyterLab sessions.
- Add an explicit `simple` Docker mode for the three-container single-host
  deployment while retaining hardened rootless mode as the default.
- Preinstall commit-pinned Shennong and ShennongData R packages, their Agent
  Skills, and their read-only MCP servers in the unified Runtime image, with
  build-time JSON-RPC smoke tests and a machine-readable toolchain inventory
  exposed through `GET /v1/info`.
- Add backward-compatible Job compatibility locks for the fixed Shennong
  Result Bundle v1 schema, canonical Runtime toolchain manifest digest, and
  exact Shennong/ShennongData version and source-commit pins. Legacy requests
  without a lock are explicitly reported as `unbound`.
- Add digest-verified UTF-8/base64 workspace staging, required Artifact roles,
  pre-success Result Bundle validation, and an authenticated bounded endpoint
  for revalidated candidate Artifact bytes.

### Changed

- Document the unified image's built-in R, Python, Pixi, Node.js, JupyterLab,
  and RStudio versions, distinguish minor-series contracts from exact pins,
  and enforce the documented R, Python, and Pixi versions during image builds.
- Upgrade the unified image's R contract from Debian `4.2.x` to the signed CRAN
  Debian `4.6.x` series required by ShennongData.
- Use the same unified Runtime image for daemon, worker, scanner, and IDE
  containers, including the hardened rootless Compose profile.
- Default Docker Compose to the public unified Runtime image and built-in stable
  network values while retaining an immutable image override for production
  rollbacks.
- Document the implemented trust boundaries, component responsibilities, state
  ownership, Job/Session lifecycles, deployment modes, residual risks and
  cross-repository contracts, with a visual architecture map in the README and
  repository-specific agent guidance.
- Record Artifact roles in journal schema v3 and expose the canonical
  toolchain-manifest SHA-256 and actual package source commits through health
  and info responses.

### Fixed

- Treat Docker's container-removal-already-in-progress conflict as an
  idempotent IDE Session stop while preserving failures for unrelated conflicts.

### Security

- Reject explicit toolchain/package lock mismatches, missing immutable Result
  Bundle inputs, mismatched output roles/digests, and recursively normalized
  credential fields before a Job can succeed.
- Read Artifact content only from the owning Job volume through a networkless
  read-only no-follow helper, then revalidate regular-file size and SHA-256 in
  the daemon. Runtime still holds no DB credential and performs no promotion.
- Hash scanner outputs through directory-relative no-follow file descriptors so
  concurrent workspace path replacement cannot redirect manifest validation.

## [1.0.0] - 2026-07-18

### Added

- Rust/Axum Runtime Daemon and strict OpenAPI v1 contract.
- Short-lived JWT verification with issuer, audience, TTL/`nbf`, exact scope,
  and exact workspace checks.
- Ed25519-only V1 production Compose wiring, with the file-backed HS256 override
  retained outside the acceptance profile solely for legacy rollback.
- Idempotent Job and IDE Session APIs backed by a SQLite recovery journal.
- Job state machine, bounded cursor logs, cancellation, timeout, reconciliation,
  and validated Artifact manifests.
- Mock executor and policy-locked dedicated-rootless Docker executor.
- Separate daemon, batch worker, and combined RStudio/JupyterLab IDE images.
- Rootless Docker user service, isolated network bootstrap, nftables public-egress
  policy, behavioral egress verification, and internal-only Compose profile.
- Root systemd path/service recovery for each RootlessKit namespace generation,
  with a root-owned policy attestation that gates Runtime health and launches.
- Least-privilege CI gates for Rust quality and tests, Dockerfile build checks,
  Compose expansion, and helper-source syntax without building the large IDE image.
- A complete rootless deployment environment example that expands the V1
  Compose profile without hidden required variables.
- Unified backup/restore guidance that records the Runtime journal alongside
  OS, DB, deployment metadata, secrets, and explicitly allowlisted workspaces.
- HTTP/WebSocket IDE proxying, exact OS-cookie filtering, Origin rewriting, and
  server-side Job/Session concurrency admission.
- Periodic reconciliation, durable terminal cleanup retry, stable Runtime
  instance labels, and bounded helper-container orphan grace.
- Runtime-enforced workspace usage ceilings and proxy-activity idle expiry.
- OS-resolved Project text inputs with digest verification, bounded per-Job
  private workspace staging, and `workspace-input://` argv resolution.
- Repeatable live rootless acceptance gate covering staged inputs, cursor logs,
  Artifact digests, failure/timeout/cancel paths, idempotency, cross-owner and
  cross-workspace isolation, locked HostConfig, and explicitly acknowledged
  restart recovery that preserves the rootless engine and workload identity.
- MIT License distribution terms.

### Security

- Workloads are forced non-root with all capabilities dropped, no-new-privileges,
  read-only root filesystems, resource limits, no host paths/devices/ports, and
  no access to Docker or control-plane networks.
- Artifact discovery runs in a distinct networkless scanner with the workspace
  mounted read-only, a bounded traversal/output size, and a separate deadline.
- Docker startup verifies rootless/seccomp/cgroup-v2 controls; nftables updates
  are atomic, automatically restored after daemon/host restart, and behavior
  tests cover live control-plane and metadata denial.
- Rootless dockerd accepts readiness notifications from its child process, and
  the IDE image pins JupyterLab 4.6.1 and supplies non-root writable SQLite,
  PID, data, and cookie-key paths for RStudio Server.
- GitHub Actions dependencies are pinned to reviewed commits and release build
  contexts exclude local secrets and generated state.
- Rust, Debian, and Pixi build stages are pinned to reviewed manifest digests;
  IDE builds now require an explicit digest-pinned worker argument.
- Workspace initialization is isolated and bounded; failed executor-handle
  persistence immediately stops/removes the created workload.
- Project input archives contain only validated regular files, use non-root
  ownership/private modes, and are uploaded through a stopped networkless
  helper whose root name is derived from the private Runtime instance ID.
- IDE backends are protected by a digest-only per-Session gateway; Runtime
  injects the raw 256-bit secret for HTTP/WebSocket and revokes live streams at
  terminal state.
- SQLite startup runs idempotent versioned migrations for journal schema
  upgrades, and executor health is part of `/v1/health`.
- Scan complete repository history for committed secrets in CI and audit the
  enabled Rust dependency graph for known advisories.

[Unreleased]: https://github.com/zerostwo/shennong-runtime/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/zerostwo/shennong-runtime/tree/v1.0.0
