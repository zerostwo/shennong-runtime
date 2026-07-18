# AGENTS.md

These instructions apply to the entire `shennong-runtime` repository.

## Mission and sources of truth

Shennong Runtime is the private, isolated execution plane for Shennong OS. The
checked-in implementation is authoritative. Keep these sources aligned:

1. Rust behavior and state transitions under `src/`;
2. the public wire schema in `protocol/openapi.yaml`;
3. executor/deployment policy under `container/`, `deployments/` and `scripts/`;
4. [docs/architecture.md](docs/architecture.md), `README.md`, `SECURITY.md` and
   `CHANGELOG.md`.

Do not describe a local dirty-tree experiment, issue proposal or roadmap item as
implemented or released. Verify it in the current branch first.

## Explore with CodeGraph first

- When `.codegraph/` exists, use CodeGraph before `rg`, `find` or opening source
  files to locate code or understand behavior.
- Start with `codegraph status`, then use one focused
  `codegraph explore "<symbols or question>"` query. Ask for named symbols and
  call paths when tracing lifecycle or security behavior.
- Use text search or direct reads afterward for non-indexed assets such as
  Markdown, shell, Dockerfiles and generated configuration, or to inspect a
  specific section already located by CodeGraph.
- If `.codegraph/` is absent, indexing is a repository-owner decision. Do not
  silently add it unless the task explicitly requests initialization.
- Commit only `.codegraph/.gitignore`; never commit the SQLite index, WAL, PID,
  socket, log or other generated CodeGraph state.
- Obey command wrappers required by any parent `AGENTS.md`. Command examples in
  this file are canonical commands and intentionally omit such wrappers.

## Repository map

- `src/main.rs`: configuration, startup reconciliation, maintenance and server
  lifecycle.
- `src/api.rs`: Axum route surface and request/response envelopes.
- `src/auth.rs`: JWT verification, exact scopes and workspace authorization.
- `src/config.rs`: environment parsing and fail-closed production validation.
- `src/model.rs`: strict protocol models, limits and Job/Session state machines.
- `src/service.rs`: admission, idempotency, monitors, expiry, cleanup and
  restart reconciliation.
- `src/journal.rs`: SQLite schema, migrations and operational recovery state.
- `src/executor.rs`: mock executor plus hardened and simple Docker modes.
- `src/proxy.rs`: Runtime-to-IDE HTTP/WebSocket proxy and header/cookie policy.
- `src/bin/shennong-ide-gateway.rs`: secret-authenticated in-container gateway.
- `protocol/openapi.yaml`: normative API V1 contract.
- `container/runtime.Dockerfile`: unified published image for daemon, worker,
  scanner, IDE and gateway roles; older split Dockerfiles are migration
  references.
- `container/`: role entrypoints, scanner, IDE and gateway runtime assets.
- `deployments/`: rootless Compose and systemd/tmpfiles integration.
- `scripts/`: rootless bootstrap, nftables reconciliation and live acceptance
  gates.
- `tests/`: API, deployment contract, migration, reconciliation and supervision
  coverage.
- `docs/architecture.md`: detailed design, ownership and cross-repo contracts.

## Architecture invariants

Changes must preserve these invariants unless an approved design explicitly
replaces them:

- Shennong OS owns users, projects, Agent Runs and durable product Job/Artifact
  records. Runtime SQLite is an operational recovery journal, not a second
  product database.
- Runtime is a private OS-only API. Shennong DB is a separate data service; no
  direct Runtime-to-DB dependency or credential is assumed.
- Only Runtime may hold the workload Docker socket. Hardened production uses a
  dedicated rootless daemon and forbids the system socket. `simple` mode is an
  explicit lower-assurance exception for a trusted single-user host; it must
  never be described as equivalent to hardened isolation.
- Callers never choose images, Docker networks, volumes, host paths, devices,
  capabilities, binds, ports or privileged flags. Server-owned profiles and
  Runtime-built HostConfig remain authoritative.
- Submitted JSON stays strict (`deny_unknown_fields`), bounded and tied to exact
  JWT subject, scope and `workspace_refs` claims. Wildcards are invalid.
- Job and Session transitions go through their declared state machines. Persist
  an executor handle before exposing `running`; failed persistence must stop and
  remove the created workload.
- Job and Session networks remain separate. Workspace-init and artifact-scanner
  helpers stay networkless; scanners use a read-only workspace mount.
- Hardened-mode launch and health remain gated by a current root-owned
  attestation for the exact RootlessKit namespace, bridges and proxy `/32`.
  Simple mode has no equivalent nftables attestation and documentation must
  preserve that distinction.
- IDE backends bind only to container loopback. API responses never expose the
  loopback target, Docker ID or raw Session secret. OS must proxy IDE traffic on
  a separate browser origin with its own Origin/CSRF controls.
- Workloads remain non-root with all capabilities dropped,
  `no-new-privileges`, read-only root filesystems, no host mounts/devices and
  bounded CPU, memory, PID, time, tmpfs, log, artifact and workspace usage.
- Cleanup and reconciliation remain restart-safe, idempotent and scoped by the
  stable Runtime instance label.

## Change workflow

1. Check `git status --short --branch` and preserve unrelated user changes.
2. Use CodeGraph to trace the affected symbols and dynamic executor calls.
3. Read the relevant tests, OpenAPI section, Compose/container policy and design
   text before editing.
4. Make the smallest coherent change. Do not weaken a fail-closed check merely
   to make local development convenient.
5. For an API or state change, update Rust models, OpenAPI, tests, architecture
   documentation and `CHANGELOG.md` in the same change.
6. Run validation proportional to risk and inspect the final diff for secrets,
   generated files and accidental business-code changes.
7. Keep commits focused. Do not push, merge, tag, publish images or operate a
   live deployment unless the user explicitly asks for that action.

## Validation commands

Minimum Rust gate:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
```

Contract and helper checks:

```bash
openapi-spec-validator protocol/openapi.yaml
bash -n scripts/*.sh
python3 -c "import ast, pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('container').rglob('*.py')]"
docker compose --env-file deployments/docker/.env.example \
  --file deployments/docker/compose.rootless.yaml config --quiet
```

Container definition check, when Docker Buildx is available:

```bash
docker buildx build --check --file container/runtime.Dockerfile .
```

Dependency/security review, when `cargo-audit` is installed:

```bash
cargo audit --ignore RUSTSEC-2023-0071
```

Run `scripts/verify-egress-policy.sh` and `scripts/verify-live-runtime.sh` only
against an explicitly authorized dedicated worker and private Runtime endpoint.
They are production acceptance gates, not ordinary unit tests.

## Documentation rules

- Keep `README.md` answer-first: purpose, a readable Mermaid system view,
  security boundary, local verification and production entry points.
- Put responsibilities, state ownership, lifecycles, deployment modes, risks,
  non-goals and cross-repository contracts in `docs/architecture.md`.
- Mermaid diagrams must match current code and use labels understandable without
  reading Rust. Update both prose and diagrams when ownership or flow changes.
- `protocol/openapi.yaml` is normative for wire behavior; prose must link to it
  instead of redefining an incompatible schema.
- Keep security claims specific and testable. Distinguish enforced controls,
  operator requirements and residual risk.

## Changelog and releases

- Follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and
  [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
- Keep `Unreleased` first. Use only the standard headings that apply: `Added`,
  `Changed`, `Deprecated`, `Removed`, `Fixed`, and `Security`.
- Add user-visible behavior, contract, deployment, security or documentation
  changes; do not paste commit logs or implementation trivia.
- Release headings use `## [X.Y.Z] - YYYY-MM-DD`. Preserve previous entries and
  add/update comparison links at the bottom.
- Never move a dirty-tree or unmerged feature into a released section. Release
  notes describe tagged repository state only.

## Security and data handling

- Never commit JWT keys, Session secrets, bearer tokens, production `.env`
  files, live database files, workspace contents, CodeGraph databases or Docker
  socket paths copied from a private host.
- Use `example.invalid`, synthetic workspace IDs and placeholder digests in
  tests/docs unless a reviewed public digest is intentionally pinned.
- Treat the Runtime journal and dedicated Docker socket as sensitive. Diagnostic
  output must not print raw JWTs or the internal Session secret.
- Do not test against `/var/run/docker.sock` or `/run/docker.sock` unless the
  user explicitly authorizes a `simple`-mode test on a disposable or trusted
  single-user host. Never use either socket for hardened-mode validation.
- Preserve user data and existing dirty worktrees. Read-only inspection does not
  authorize modifying or committing those changes.
