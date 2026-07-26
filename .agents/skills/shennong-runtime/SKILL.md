---
name: shennong-runtime
description: Submit and verify compatibility-locked Shennong Runtime jobs without crossing the OS, Runtime, or DB trust boundaries.
---

# Use Shennong Runtime safely

Use this skill when an authorized Shennong OS workflow must inspect Runtime
capabilities, submit a batch Job, follow its state, or retrieve candidate
Artifact bytes.

## Required boundary

- Runtime is a private OS-only execution API.
- Use a short-lived OS-issued JWT with exact scopes and `workspace_refs`.
- Never give Runtime or a workload ShennongDB credentials, an admin key, a host
  path, a Docker socket, or a caller-selected image/network/volume.
- A Runtime `succeeded` state proves bounded execution and candidate validation.
  It does not prove OS/DB upload, authorization, or durable Artifact promotion.

## Compatibility-locked Job workflow

1. Call `GET /v1/health` and require a healthy executor plus
   `r_toolchain_status=verified`.
2. Call `GET /v1/info`. Copy, without guessing:
   - `r_toolchain.schema`;
   - `r_toolchain_sha256`;
   - `r_toolchain.packages.Shennong` and `.ShennongData`;
   - `package_commits.Shennong` and `.ShennongData`.
3. Submit `POST /v1/jobs` with a unique `Idempotency-Key` and:
   - `compatibility_lock.result_bundle_schema` equal to
     `shennong.dev/analysis-result-bundle/v1`;
   - `compatibility_lock.runtime_toolchain` copied from step 2;
   - both package version/commit pairs copied from step 2;
   - exactly one required Artifact rule whose role is
     `analysis_result_bundle`;
   - required roles for other candidate outputs that must exist.
4. For text inputs use `encoding=utf8` or omit it. For binary inputs use
   `encoding=base64`; `sha256` always covers decoded bytes. Keep the complete
   request within 32 files, 1 MiB per file, and 1 MiB decoded total.
5. Poll the Job. Treat `compatibility_status=unbound` as legacy, not verified.
   An explicit mismatch is a non-retryable contract error.
6. A compatibility-locked Job can succeed only after Runtime validates:
   - the fixed seven-field Result Bundle v1 boundary;
   - at least one immutable input reference with identifier, revision, and
     SHA-256 digest;
   - a successful validation record and provenance;
   - candidate Artifact roles/paths/digests against the scanner manifest;
   - absence of the frozen credential-field names at every JSON depth.
7. List `GET /v1/jobs/{job_id}/artifacts`, then retrieve one candidate with
   `GET /v1/jobs/{job_id}/artifacts/{artifact_id}/content`. Verify the
   `X-Content-Sha256` header again before an authorized OS workflow promotes
   those bytes into durable storage.

## Failure interpretation

- `401`/`403`: obtain a new narrowly scoped OS JWT; do not weaken Runtime auth.
- `409`: inspect idempotency reuse or Job terminal state.
- `422` for compatibility: refresh `/v1/info`; never manufacture a commit or
  downgrade the request silently.
- `422` for Artifact bytes: the workspace file changed or violated the
  path/size/digest contract. Do not promote it.
- `unbound`: the Job omitted a lock. It may run for compatibility, but it is
  not evidence that the current Shennong toolchain produced a Result Bundle.

The normative wire schema is `protocol/openapi.yaml`.
