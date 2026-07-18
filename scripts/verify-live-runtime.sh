#!/usr/bin/env bash
# Live, destructive acceptance gate for the dedicated rootless Runtime executor.
#
# Scope: creates uniquely named Jobs and exactly two uniquely named workspace
# volumes. Cleanup is limited to the Job IDs returned by this run and the two
# preflight-verified-new volumes whose labels still match those workspaces.
set -euo pipefail

: "${DOCKER_HOST:?set DOCKER_HOST to the dedicated rootless Docker socket}"
: "${SHENNONG_LIVE_RUNTIME_URL:?set SHENNONG_LIVE_RUNTIME_URL to the private Runtime API base URL}"
: "${SHENNONG_LIVE_JWT_PRIVATE_KEY_FILE:?set SHENNONG_LIVE_JWT_PRIVATE_KEY_FILE to the OS Ed25519 private key}"

readonly job_network="${SHENNONG_JOB_EGRESS_NETWORK:-shennong-job-egress}"
readonly worker_profile="${SHENNONG_LIVE_WORKER_PROFILE:-cpu-small}"
readonly jwt_issuer="${SHENNONG_LIVE_JWT_ISSUER:-shennong-os}"
readonly jwt_audience="${SHENNONG_LIVE_JWT_AUDIENCE:-shennong-runtime}"
readonly jwt_ttl_seconds="${SHENNONG_LIVE_JWT_TTL_SECONDS:-110}"
readonly poll_seconds="${SHENNONG_LIVE_POLL_SECONDS:-45}"
readonly runtime_url="${SHENNONG_LIVE_RUNTIME_URL%/}"

fail() {
  echo "live Runtime acceptance failed: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

for command_name in curl docker jq openssl python3 sha256sum; do
  require_command "${command_name}"
done

if [[ ! "${jwt_ttl_seconds}" =~ ^[0-9]+$ ]] || (( jwt_ttl_seconds < 30 || jwt_ttl_seconds > 120 )); then
  fail "SHENNONG_LIVE_JWT_TTL_SECONDS must be between 30 and 120"
fi
if [[ ! "${poll_seconds}" =~ ^[0-9]+$ ]] || (( poll_seconds < 10 || poll_seconds > 180 )); then
  fail "SHENNONG_LIVE_POLL_SECONDS must be between 10 and 180"
fi
case "${runtime_url}" in
  http://*|https://*) ;;
  *) fail "SHENNONG_LIVE_RUNTIME_URL must be an HTTP(S) URL" ;;
esac
case "${DOCKER_HOST}" in
  unix://*) ;;
  *) fail "DOCKER_HOST must name the dedicated rootless unix socket" ;;
esac

docker_socket="${DOCKER_HOST#unix://}"
docker_socket_real="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${docker_socket}")"
case "${docker_socket_real}" in
  /var/run/docker.sock|/run/docker.sock) fail "refusing the system Docker socket" ;;
esac
[[ -S "${docker_socket_real}" ]] || fail "DOCKER_HOST does not resolve to a unix socket"
[[ -f "${SHENNONG_LIVE_JWT_PRIVATE_KEY_FILE}" && -r "${SHENNONG_LIVE_JWT_PRIVATE_KEY_FILE}" ]] \
  || fail "OS JWT private key is not a readable regular file"
python3 -c '
import os, sys
mode = os.stat(sys.argv[1]).st_mode
owner_can_read = mode & 0o400 != 0
unsafe_permissions = mode & 0o027
raise SystemExit(0 if owner_can_read and unsafe_permissions == 0 else 1)
' "${SHENNONG_LIVE_JWT_PRIVATE_KEY_FILE}" \
  || fail "OS JWT private key must be owner-readable and reject group write/execute and all world access"

docker_cli=(docker --host "${DOCKER_HOST}")
security_options="$("${docker_cli[@]}" info --format '{{json .SecurityOptions}}')"
jq -e 'any(.[]; split(",") | any(. == "name=rootless"))' <<<"${security_options}" >/dev/null \
  || fail "selected Docker daemon does not report rootless mode"
"${docker_cli[@]}" network inspect "${job_network}" >/dev/null \
  || fail "managed Job network is absent: ${job_network}"
rootless_engine_id="$("${docker_cli[@]}" info --format '{{.ID}}')"
[[ -n "${rootless_engine_id}" ]] || fail "selected rootless Docker daemon has no engine ID"
readonly rootless_engine_id

tmp_dir="$(mktemp -d -t shennong-runtime-live.XXXXXXXX)"
chmod 0700 "${tmp_dir}"
run_id="live-$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 6)"
readonly run_id
readonly workspace_a="ws_${run_id//-/_}_a"
readonly workspace_b="ws_${run_id//-/_}_b"
readonly subject_a="acceptance_${run_id//-/_}_a"
readonly subject_b="acceptance_${run_id//-/_}_b"
volume_a="shennong-ws-$(printf '%s' "${workspace_a}" | sha256sum | awk '{print substr($1,1,32)}')"
volume_b="shennong-ws-$(printf '%s' "${workspace_b}" | sha256sum | awk '{print substr($1,1,32)}')"
readonly volume_a volume_b

declare -a created_job_ids=()
declare -A job_header_files=()
declare -A created_volumes=(
  ["${volume_a}"]="${workspace_a}"
  ["${volume_b}"]="${workspace_b}"
)

safe_remove_volume() {
  local volume="$1"
  local expected_workspace="$2"
  local labels
  if ! labels="$("${docker_cli[@]}" volume inspect --format '{{json .Labels}}' "${volume}" 2>/dev/null)"; then
    return 0
  fi
  if ! jq -e --arg workspace "${expected_workspace}" '
      .["dev.shennong.managed"] == "true"
      and .["dev.shennong.kind"] == "workspace-volume"
      and .["dev.shennong.workspace_ref"] == $workspace
      and (.["dev.shennong.instance"] | type == "string" and length > 0)
    ' <<<"${labels}" >/dev/null; then
    echo "refusing to remove volume with mismatched ownership labels: ${volume}" >&2
    return 1
  fi
  "${docker_cli[@]}" volume rm "${volume}" >/dev/null
}

cleanup() {
  local job_id container_id header_file volume expected_workspace
  set +e
  for job_id in "${created_job_ids[@]}"; do
    header_file="${job_header_files[${job_id}]:-}"
    if [[ -n "${header_file}" && -r "${header_file}" ]]; then
      curl --silent --show-error --max-time 4 \
        --header "@${header_file}" \
        --request POST \
        --output /dev/null \
        "${runtime_url}/v1/jobs/${job_id}/cancel" >/dev/null 2>&1
    fi
    while IFS= read -r container_id; do
      [[ -n "${container_id}" ]] || continue
      if "${docker_cli[@]}" inspect "${container_id}" \
        | jq -e --arg id "${job_id}" '
            .[0].Config.Labels["dev.shennong.managed"] == "true"
            and (
              .[0].Config.Labels["dev.shennong.kind"] == "job"
              or .[0].Config.Labels["dev.shennong.kind"] == "artifact-scanner"
            )
            and .[0].Config.Labels["dev.shennong.job_id"] == $id
          ' >/dev/null 2>&1; then
        "${docker_cli[@]}" rm --force "${container_id}" >/dev/null 2>&1
      fi
    done < <("${docker_cli[@]}" ps --all --quiet \
      --filter "label=dev.shennong.managed=true" \
      --filter "label=dev.shennong.job_id=${job_id}")
  done
  for volume in "${!created_volumes[@]}"; do
    expected_workspace="${created_volumes[${volume}]}"
    safe_remove_volume "${volume}" "${expected_workspace}" \
      || echo "warning: exact acceptance volume could not be removed: ${volume}" >&2
  done
  rm -rf -- "${tmp_dir}"
}
trap cleanup EXIT INT TERM

for volume in "${volume_a}" "${volume_b}"; do
  if "${docker_cli[@]}" volume inspect "${volume}" >/dev/null 2>&1; then
    fail "random acceptance workspace volume already exists; refusing to reuse it: ${volume}"
  fi
done

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

write_jwt_header() {
  local output_file="$1"
  local subject="$2"
  local workspace="$3"
  local now expires jwt_header jwt_payload signing_input signing_input_file signature_file
  now="$(date -u +%s)"
  expires="$((now + jwt_ttl_seconds))"
  jwt_header="$(printf '%s' '{"alg":"EdDSA","typ":"JWT"}' | base64url)"
  jwt_payload="$(python3 - "${jwt_issuer}" "${jwt_audience}" "${subject}" "${workspace}" "${now}" "${expires}" "${run_id}" <<'PY'
import base64
import json
import sys
import uuid

issuer, audience, subject, workspace, issued, expires, run_id = sys.argv[1:]
payload = {
    "iss": issuer,
    "aud": audience,
    "sub": subject,
    "iat": int(issued),
    "nbf": int(issued),
    "exp": int(expires),
    "jti": f"{run_id}:{uuid.uuid4()}",
    "scopes": ["runtime:jobs:write", "runtime:jobs:read", "runtime:jobs:cancel"],
    "workspace_refs": [workspace],
}
encoded = base64.urlsafe_b64encode(
    json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
).rstrip(b"=")
sys.stdout.write(encoded.decode())
PY
  )"
  signing_input="${jwt_header}.${jwt_payload}"
  signing_input_file="${tmp_dir}/signing-input-$(openssl rand -hex 6).txt"
  signature_file="${tmp_dir}/signature-$(openssl rand -hex 6).bin"
  printf '%s' "${signing_input}" >"${signing_input_file}"
  chmod 0600 "${signing_input_file}"
  openssl pkeyutl -sign -rawin \
    -inkey "${SHENNONG_LIVE_JWT_PRIVATE_KEY_FILE}" \
    -in "${signing_input_file}" \
    -out "${signature_file}"
  printf 'Authorization: Bearer %s.%s\n' \
    "${signing_input}" "$(base64url <"${signature_file}")" >"${output_file}"
  chmod 0600 "${output_file}"
  rm -f -- "${signing_input_file}" "${signature_file}"
}

readonly header_a="${tmp_dir}/auth-a.header"
readonly header_b="${tmp_dir}/auth-b.header"
readonly header_a_wrong_workspace="${tmp_dir}/auth-a-wrong-workspace.header"
write_jwt_header "${header_a}" "${subject_a}" "${workspace_a}"
write_jwt_header "${header_b}" "${subject_b}" "${workspace_b}"
write_jwt_header "${header_a_wrong_workspace}" "${subject_a}" "${workspace_b}"

request() {
  local header_file="$1"
  local method="$2"
  local path="$3"
  local expected_status="$4"
  local output_file="$5"
  local body_file="${6:-}"
  local idempotency_key="${7:-}"
  local -a arguments=(
    --silent --show-error --max-time 10
    --header "@${header_file}"
    --request "${method}"
    --output "${output_file}"
    --write-out '%{http_code}'
  )
  if [[ -n "${body_file}" ]]; then
    arguments+=(--header 'Content-Type: application/json' --data-binary "@${body_file}")
  fi
  if [[ -n "${idempotency_key}" ]]; then
    arguments+=(--header "Idempotency-Key: ${idempotency_key}")
  fi
  local status
  status="$(curl "${arguments[@]}" "${runtime_url}${path}")"
  if [[ "${status}" != "${expected_status}" ]]; then
    echo "unexpected ${method} ${path} status: wanted ${expected_status}, got ${status}" >&2
    jq -c '{error: .error // "unparseable response"}' "${output_file}" >&2 2>/dev/null || true
    return 1
  fi
}

public_request() {
  local path="$1"
  local output_file="$2"
  local status
  status="$(curl --silent --show-error --max-time 5 \
    --output "${output_file}" --write-out '%{http_code}' "${runtime_url}${path}")"
  [[ "${status}" == "200" ]] || fail "public Runtime endpoint ${path} returned ${status}"
}

health_file="${tmp_dir}/health.json"
info_file="${tmp_dir}/info.json"
public_request /v1/health "${health_file}"
jq -e '.status == "ok" and .journal == "ok" and .executor == "docker-rootless"' \
  "${health_file}" >/dev/null || fail "Runtime health is not backed by the rootless executor"
public_request /v1/info "${info_file}"
jq -e --arg profile "${worker_profile}" '
  .service == "shennong-runtime"
  and .executor == "docker-rootless"
  and .network_policy == "internet_only"
  and (.worker_profiles | index($profile) != null)
' "${info_file}" >/dev/null || fail "Runtime info does not expose the requested rootless worker profile"

make_resources() {
  local timeout_seconds="$1"
  jq -n --argjson timeout "${timeout_seconds}" '{
    cpus: 0.5,
    memory_bytes: 268435456,
    pids: 32,
    timeout_seconds: $timeout,
    tmpfs_bytes: 33554432,
    max_log_bytes: 1048576,
    max_artifact_bytes: 1048576,
    max_workspace_bytes: 67108864
  }'
}

make_inline_job() {
  local workspace="$1"
  local timeout_seconds="$2"
  local python_code="$3"
  local output_file="$4"
  jq -n \
    --arg workspace "${workspace}" \
    --arg profile "${worker_profile}" \
    --arg code "${python_code}" \
    --argjson resources "$(make_resources "${timeout_seconds}")" '
    {
      api_version: "shennong.dev/v1",
      workspace_ref: $workspace,
      worker_profile: $profile,
      argv: ["python3", "-c", $code],
      resources: $resources,
      network: "internet_only",
      workspace_files: [],
      artifact_rules: []
    }
  ' >"${output_file}"
}

make_success_job() {
  local workspace="$1"
  local label="$2"
  local input_text="$3"
  local artifact_path="$4"
  local forbidden_path="$5"
  local output_file="$6"
  local input_sha runner_content runner_sha expected_artifact
  input_sha="$(printf '%s' "${input_text}" | sha256sum | awk '{print $1}')"
  runner_content='import hashlib,pathlib,sys
source=pathlib.Path(sys.argv[1])
target=pathlib.Path(sys.argv[2])
expected_input_sha=sys.argv[3]
label=sys.argv[4]
forbidden=pathlib.Path(sys.argv[5])
payload=source.read_bytes()
if hashlib.sha256(payload).hexdigest()!=expected_input_sha:
    raise SystemExit(65)
if forbidden.exists():
    raise SystemExit(66)
target.parent.mkdir(parents=True,exist_ok=True)
target.write_bytes(b"verified:"+payload)
print("workspace-file-ok:"+label,flush=True)
print("workspace-isolation-ok:"+label,flush=True)'
  runner_sha="$(printf '%s' "${runner_content}" | sha256sum | awk '{print $1}')"
  expected_artifact="$(printf 'verified:%s' "${input_text}" | sha256sum | awk '{print $1}')"
  jq -n \
    --arg workspace "${workspace}" \
    --arg profile "${worker_profile}" \
    --arg runner "${runner_content}" \
    --arg runner_sha "${runner_sha}" \
    --arg input "${input_text}" \
    --arg input_sha "${input_sha}" \
    --arg artifact "${artifact_path}" \
    --arg forbidden "${forbidden_path}" \
    --arg label "${label}" \
    --arg expected_artifact "${expected_artifact}" \
    --argjson resources "$(make_resources 20)" '
    {
      api_version: "shennong.dev/v1",
      workspace_ref: $workspace,
      worker_profile: $profile,
      argv: [
        "python3",
        "workspace-input://acceptance/runner.py",
        "workspace-input://acceptance/input.txt",
        $artifact,
        $input_sha,
        $label,
        $forbidden
      ],
      resources: $resources,
      network: "internet_only",
      workspace_files: [
        {path: "acceptance/runner.py", content: $runner, sha256: $runner_sha},
        {path: "acceptance/input.txt", content: $input, sha256: $input_sha}
      ],
      artifact_rules: [{path: $artifact, kind: "report"}],
      _acceptance_expected_artifact_sha256: $expected_artifact
    }
  ' >"${output_file}"
  jq 'del(._acceptance_expected_artifact_sha256)' "${output_file}" >"${output_file}.request"
  mv "${output_file}.request" "${output_file}"
  printf '%s' "${expected_artifact}" >"${output_file}.expected-sha256"
}

register_job() {
  local job_id="$1"
  local header_file="$2"
  created_job_ids+=("${job_id}")
  job_header_files["${job_id}"]="${header_file}"
}

submit_job() {
  local header_file="$1"
  local key="$2"
  local body_file="$3"
  local output_file="$4"
  request "${header_file}" POST /v1/jobs 202 "${output_file}" "${body_file}" "${key}"
  jq -er '.id' "${output_file}"
}

wait_for_state() {
  local header_file="$1"
  local job_id="$2"
  local expected_state="$3"
  local output_file="$4"
  local deadline state
  deadline="$((SECONDS + poll_seconds))"
  while (( SECONDS < deadline )); do
    request "${header_file}" GET "/v1/jobs/${job_id}" 200 "${output_file}"
    state="$(jq -er '.state' "${output_file}")"
    case "${state}" in
      succeeded|failed|cancelled|timed_out|lost)
        [[ "${state}" == "${expected_state}" ]] \
          || fail "Job ${job_id} reached ${state}; expected ${expected_state}"
        return 0
        ;;
    esac
    sleep 0.25
  done
  fail "Job ${job_id} did not reach ${expected_state} within ${poll_seconds}s"
}

wait_for_running_container() {
  local header_file="$1"
  local job_id="$2"
  local output_file="$3"
  local deadline state container_ids container_count
  deadline="$((SECONDS + poll_seconds))"
  while (( SECONDS < deadline )); do
    request "${header_file}" GET "/v1/jobs/${job_id}" 200 "${output_file}"
    state="$(jq -er '.state' "${output_file}")"
    case "${state}" in
      succeeded|failed|cancelled|timed_out|lost)
        fail "Job ${job_id} reached ${state} before its running container could be inspected"
        ;;
    esac
    container_ids="$("${docker_cli[@]}" ps --quiet \
      --filter "label=dev.shennong.managed=true" \
      --filter "label=dev.shennong.kind=job" \
      --filter "label=dev.shennong.job_id=${job_id}")"
    container_count="$(awk 'NF { count += 1 } END { print count + 0 }' <<<"${container_ids}")"
    if [[ "${state}" == "running" && "${container_count}" == "1" ]]; then
      printf '%s\n' "${container_ids}"
      return 0
    fi
    if (( container_count > 1 )); then
      fail "more than one running container claims Job ${job_id}"
    fi
    sleep 0.1
  done
  fail "Job ${job_id} did not expose exactly one running container within ${poll_seconds}s"
}

assert_success_outputs() {
  local header_file="$1"
  local job_id="$2"
  local label="$3"
  local artifact_path="$4"
  local expected_sha="$5"
  local logs_file artifacts_file
  logs_file="${tmp_dir}/logs-${job_id}.json"
  artifacts_file="${tmp_dir}/artifacts-${job_id}.json"
  request "${header_file}" GET "/v1/jobs/${job_id}/logs?after=0&limit=200" 200 "${logs_file}"
  jq -e --arg marker "workspace-file-ok:${label}" '
    .next_cursor > 0
    and any(.entries[]; .stream == "stdout" and (.message | contains($marker)))
  ' "${logs_file}" >/dev/null || fail "staged workspace content was not confirmed in Job logs"
  jq -e --arg marker "workspace-isolation-ok:${label}" '
    any(.entries[]; .stream == "stdout" and (.message | contains($marker)))
  ' "${logs_file}" >/dev/null || fail "workspace isolation sentinel was not confirmed in Job logs"
  request "${header_file}" GET "/v1/jobs/${job_id}/artifacts" 200 "${artifacts_file}"
  jq -e --arg path "${artifact_path}" --arg digest "${expected_sha}" '
    (.artifacts | length) == 1
    and .artifacts[0].relative_path == $path
    and .artifacts[0].kind == "report"
    and .artifacts[0].sha256 == $digest
    and .artifacts[0].size_bytes > 0
  ' "${artifacts_file}" >/dev/null || fail "validated Artifact manifest or digest does not match"
}

assert_denied() {
  local header_file="$1"
  local path="$2"
  local expected_status="$3"
  local output_file
  output_file="${tmp_dir}/denied-$(openssl rand -hex 6).json"
  request "${header_file}" GET "${path}" "${expected_status}" "${output_file}"
  jq -e --arg code "$([[ "${expected_status}" == "403" ]] && printf forbidden || printf not_found)" \
    '.error.code == $code' "${output_file}" >/dev/null \
    || fail "isolation response did not use the expected fail-closed error"
}

success_a_body="${tmp_dir}/success-a.json"
success_b_body="${tmp_dir}/success-b.json"
artifact_a="acceptance-${run_id}/artifact-a.txt"
artifact_b="acceptance-${run_id}/artifact-b.txt"
make_success_job "${workspace_a}" "${run_id}:a" "alpha-${run_id}" "${artifact_a}" \
  "${artifact_b}" "${success_a_body}"
make_success_job "${workspace_b}" "${run_id}:b" "beta-${run_id}" "${artifact_b}" \
  "${artifact_a}" "${success_b_body}"

success_a_response="${tmp_dir}/success-a-response.json"
success_a_id="$(submit_job "${header_a}" "${run_id}:success-a" "${success_a_body}" "${success_a_response}")"
register_job "${success_a_id}" "${header_a}"
wait_for_state "${header_a}" "${success_a_id}" succeeded "${tmp_dir}/success-a-final.json"
assert_success_outputs "${header_a}" "${success_a_id}" "${run_id}:a" "${artifact_a}" \
  "$(<"${success_a_body}.expected-sha256")"

success_b_response="${tmp_dir}/success-b-response.json"
success_b_id="$(submit_job "${header_b}" "${run_id}:success-b" "${success_b_body}" "${success_b_response}")"
register_job "${success_b_id}" "${header_b}"
wait_for_state "${header_b}" "${success_b_id}" succeeded "${tmp_dir}/success-b-final.json"
assert_success_outputs "${header_b}" "${success_b_id}" "${run_id}:b" "${artifact_b}" \
  "$(<"${success_b_body}.expected-sha256")"

# Same owner but a JWT for the wrong workspace is forbidden. A different owner
# is hidden behind 404. Both boundaries apply to Job, log, and Artifact reads.
for suffix in "" "/logs?after=0&limit=1" "/artifacts"; do
  assert_denied "${header_a_wrong_workspace}" "/v1/jobs/${success_a_id}${suffix}" 403
  assert_denied "${header_b}" "/v1/jobs/${success_a_id}${suffix}" 404
  assert_denied "${header_a}" "/v1/jobs/${success_b_id}${suffix}" 404
done
denied_submit="${tmp_dir}/denied-submit.json"
request "${header_b}" POST /v1/jobs 403 "${denied_submit}" "${success_a_body}" "${run_id}:cross-submit"
jq -e '.error.code == "forbidden"' "${denied_submit}" >/dev/null \
  || fail "cross-workspace submit was not rejected by workspace authorization"

# Keep every acceptance credential short-lived without making a slower worker
# image pull or Artifact scan race the JWT expiry.
write_jwt_header "${header_a}" "${subject_a}" "${workspace_a}"

failure_body="${tmp_dir}/failure.json"
make_inline_job "${workspace_a}" 20 \
  'import sys; print("expected-nonzero", file=sys.stderr, flush=True); raise SystemExit(7)' \
  "${failure_body}"
failure_response="${tmp_dir}/failure-response.json"
failure_id="$(submit_job "${header_a}" "${run_id}:failure" "${failure_body}" "${failure_response}")"
register_job "${failure_id}" "${header_a}"
wait_for_state "${header_a}" "${failure_id}" failed "${tmp_dir}/failure-final.json"
jq -e '.exit_code == 7' "${tmp_dir}/failure-final.json" >/dev/null \
  || fail "nonzero Job did not preserve exit code 7"
failure_logs="${tmp_dir}/failure-logs.json"
request "${header_a}" GET "/v1/jobs/${failure_id}/logs?after=0&limit=200" 200 "${failure_logs}"
jq -e 'any(.entries[]; .stream == "stderr" and (.message | contains("expected-nonzero")))' \
  "${failure_logs}" >/dev/null || fail "nonzero stderr was not journaled"

timeout_body="${tmp_dir}/timeout.json"
make_inline_job "${workspace_a}" 2 \
  'import time; print("expected-timeout", flush=True); time.sleep(30)' \
  "${timeout_body}"
timeout_response="${tmp_dir}/timeout-response.json"
timeout_id="$(submit_job "${header_a}" "${run_id}:timeout" "${timeout_body}" "${timeout_response}")"
register_job "${timeout_id}" "${header_a}"
wait_for_state "${header_a}" "${timeout_id}" timed_out "${tmp_dir}/timeout-final.json"

cancel_body="${tmp_dir}/cancel.json"
make_inline_job "${workspace_a}" 90 \
  'import time; print("ready-for-inspection", flush=True); time.sleep(90)' \
  "${cancel_body}"
cancel_response="${tmp_dir}/cancel-response.json"
cancel_key="${run_id}:cancel"
cancel_id="$(submit_job "${header_a}" "${cancel_key}" "${cancel_body}" "${cancel_response}")"
register_job "${cancel_id}" "${header_a}"

replay_response="${tmp_dir}/replay-response.json"
replay_id="$(submit_job "${header_a}" "${cancel_key}" "${cancel_body}" "${replay_response}")"
[[ "${replay_id}" == "${cancel_id}" ]] || fail "idempotency replay created a second Job"
conflict_body="${tmp_dir}/conflict.json"
jq '.resources.pids = 33' "${cancel_body}" >"${conflict_body}"
conflict_response="${tmp_dir}/conflict-response.json"
request "${header_a}" POST /v1/jobs 409 "${conflict_response}" "${conflict_body}" "${cancel_key}"
jq -e '.error.code == "conflict"' "${conflict_response}" >/dev/null \
  || fail "changed idempotency replay did not fail closed"

cancel_container="$(wait_for_running_container "${header_a}" "${cancel_id}" \
  "${tmp_dir}/cancel-running.json")"
inspect_file="${tmp_dir}/cancel-inspect.json"
"${docker_cli[@]}" inspect "${cancel_container}" >"${inspect_file}"
jq -e \
  --arg id "${cancel_id}" \
  --arg network "${job_network}" '
  .[0] as $container
  | $container.Name == ("/shennong-job-" + $id)
    and $container.State.Running == true
    and $container.Config.User == "65532:65532"
    and $container.HostConfig.ReadonlyRootfs == true
    and $container.HostConfig.Privileged == false
    and $container.HostConfig.AutoRemove == false
    and $container.HostConfig.PublishAllPorts == false
    and (($container.HostConfig.CapDrop | sort) == ["ALL"])
    and ($container.HostConfig.SecurityOpt | index("no-new-privileges=true") != null)
    and ($container.HostConfig.SecurityOpt | index("seccomp=builtin") != null)
    and (($container.HostConfig.Binds // []) | length == 0)
    and (($container.HostConfig.Devices // []) | length == 0)
    and (($container.HostConfig.DeviceRequests // []) | length == 0)
    and (($container.HostConfig.PortBindings // {}) | length == 0)
    and (($container.Config.ExposedPorts // {}) | length == 0)
    and $container.HostConfig.NetworkMode == $network
    and (($container.HostConfig.PidMode // "") == "")
    and $container.HostConfig.PidsLimit == 32
    and $container.HostConfig.NanoCpus == 500000000
    and $container.HostConfig.Memory == 268435456
    and $container.HostConfig.MemorySwap == 268435456
    and $container.HostConfig.IpcMode == "private"
    and (($container.Mounts // []) | all(.Type != "bind"))
    and ([($container.Mounts // [])[]
      | select(.Type == "volume" and .Destination == "/workspace" and .RW == true)
    ] | length) == 1
    and ($container.HostConfig.Tmpfs["/tmp"] | contains("nosuid,nodev,noexec"))
    and (($container.NetworkSettings.Networks | keys) == [$network])
    and $container.Config.Labels["dev.shennong.managed"] == "true"
    and $container.Config.Labels["dev.shennong.kind"] == "job"
    and $container.Config.Labels["dev.shennong.job_id"] == $id
    and ($container.Config.Labels["dev.shennong.instance"] | length > 0)
' "${inspect_file}" >/dev/null || fail "running Job container violates the locked-down launch contract"

cancel_result="${tmp_dir}/cancel-result.json"
request "${header_a}" POST "/v1/jobs/${cancel_id}/cancel" 200 "${cancel_result}"
jq -e '.state == "cancelled"' "${cancel_result}" >/dev/null \
  || fail "cancel request did not reach cancelled"
cancel_replay="${tmp_dir}/cancel-replay.json"
request "${header_a}" POST "/v1/jobs/${cancel_id}/cancel" 200 "${cancel_replay}"
jq -e --arg id "${cancel_id}" '.id == $id and .state == "cancelled"' "${cancel_replay}" >/dev/null \
  || fail "repeated cancellation was not idempotent"

if [[ "${SHENNONG_LIVE_ENABLE_RESTART:-0}" == "1" ]]; then
  [[ "${SHENNONG_LIVE_RESTART_ACK:-}" == "restart-runtime-daemon-only" ]] \
    || fail "set SHENNONG_LIVE_RESTART_ACK=restart-runtime-daemon-only to authorize the restart gate"
  : "${SHENNONG_LIVE_RESTART_HOOK:?set an absolute executable hook when restart recovery is enabled}"
  [[ "${SHENNONG_LIVE_RESTART_HOOK}" == /* ]] \
    || fail "SHENNONG_LIVE_RESTART_HOOK must be an absolute path"
  [[ -x "${SHENNONG_LIVE_RESTART_HOOK}" ]] \
    || fail "SHENNONG_LIVE_RESTART_HOOK must be executable"
  restart_header="${tmp_dir}/auth-restart.header"
  write_jwt_header "${restart_header}" "${subject_a}" "${workspace_a}"
  restart_body="${tmp_dir}/restart.json"
  make_inline_job "${workspace_a}" 60 \
    'import time; print("restart-job-started", flush=True); time.sleep(20); print("restart-job-recovered", flush=True)' \
    "${restart_body}"
  restart_response="${tmp_dir}/restart-response.json"
  restart_id="$(submit_job "${restart_header}" "${run_id}:restart" "${restart_body}" "${restart_response}")"
  register_job "${restart_id}" "${restart_header}"
  restart_container="$(wait_for_running_container "${restart_header}" "${restart_id}" \
    "${tmp_dir}/restart-running.json")"
  "${SHENNONG_LIVE_RESTART_HOOK}"
  [[ "$("${docker_cli[@]}" info --format '{{.ID}}')" == "${rootless_engine_id}" ]] \
    || fail "restart hook changed the selected rootless workload daemon"
  "${docker_cli[@]}" inspect "${restart_container}" \
    | jq -e --arg id "${restart_id}" '
        .[0].Config.Labels["dev.shennong.managed"] == "true"
        and .[0].Config.Labels["dev.shennong.kind"] == "job"
        and .[0].Config.Labels["dev.shennong.job_id"] == $id
      ' >/dev/null || fail "restart hook replaced or removed the in-flight workload container"
  restart_health_ok=0
  for _ in $(seq 1 60); do
    if curl --silent --fail --max-time 2 "${runtime_url}/v1/health" >/dev/null 2>&1; then
      restart_health_ok=1
      break
    fi
    sleep 0.5
  done
  [[ "${restart_health_ok}" == "1" ]] || fail "Runtime did not become healthy after the restart hook"
  wait_for_state "${restart_header}" "${restart_id}" succeeded "${tmp_dir}/restart-final.json"
  restart_logs="${tmp_dir}/restart-logs.json"
  request "${restart_header}" GET "/v1/jobs/${restart_id}/logs?after=0&limit=200" 200 "${restart_logs}"
  jq -e 'any(.entries[]; .message | contains("restart-job-recovered"))' \
    "${restart_logs}" >/dev/null || fail "in-flight Job was not recovered after Runtime restart"
elif [[ -n "${SHENNONG_LIVE_RESTART_HOOK:-}" || -n "${SHENNONG_LIVE_RESTART_ACK:-}" ]]; then
  fail "restart hook or acknowledgment was supplied without SHENNONG_LIVE_ENABLE_RESTART=1"
fi

echo "live Runtime acceptance passed: rootless launch policy, staged inputs, logs, Artifact digest, failure, timeout, cancellation, idempotency, and workspace/owner isolation verified (${run_id})"
