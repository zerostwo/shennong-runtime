#!/bin/sh
set -eu

config_dir=${SHENNONG_CONFIG_DIR:-/config}
data_dir=${SHENNONG_DATA_DIR:-/var/lib/shennong-runtime}
public_key=${SHENNONG_JWT_PUBLIC_KEY_FILE:-$config_dir/runtime-jwt-ed25519-public.pem}

if [ "$#" -ge 1 ] && [ "$1" = "shennong-runtime" ]; then
  attempts=0
  while [ ! -s "$public_key" ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 120 ]; then
      echo "runtime public key was not initialized at $public_key" >&2
      exit 1
    fi
    sleep 1
  done

  mkdir -p "$data_dir"
  image=${SHENNONG_RUNTIME_IMAGE:-zerostwo/shennong-runtime:latest}
  export SHENNONG_RUNTIME_LISTEN=${SHENNONG_RUNTIME_LISTEN:-0.0.0.0:7000}
  export SHENNONG_RUNTIME_HEALTH_ADDR=${SHENNONG_RUNTIME_HEALTH_ADDR:-127.0.0.1:7000}
  export SHENNONG_RUNTIME_DATABASE_URL=${SHENNONG_RUNTIME_DATABASE_URL:-sqlite://$data_dir/runtime.db?mode=rwc}
  export SHENNONG_EXECUTOR=${SHENNONG_EXECUTOR:-docker}
  export SHENNONG_RUNTIME_DOCKER_MODE=${SHENNONG_RUNTIME_DOCKER_MODE:-hardened}
  export SHENNONG_ROOTLESS_DOCKER_SOCKET=${SHENNONG_ROOTLESS_DOCKER_SOCKET:-${SHENNONG_DOCKER_SOCKET:-/run/shennong/docker.sock}}
  export SHENNONG_JOB_EGRESS_NETWORK=${SHENNONG_JOB_EGRESS_NETWORK:-shennong-job-egress}
  export SHENNONG_SESSION_PROXY_NETWORK=${SHENNONG_SESSION_PROXY_NETWORK:-shennong-session-proxy}
  export SHENNONG_RUNTIME_INSTANCE_ID=${SHENNONG_RUNTIME_INSTANCE_ID:-runtime-1}
  export SHENNONG_JWT_ALGORITHM=${SHENNONG_JWT_ALGORITHM:-EdDSA}
  export SHENNONG_JWT_PUBLIC_KEY_FILE=$public_key
  export SHENNONG_JWT_ISSUER=${SHENNONG_JWT_ISSUER:-shennong-os}
  export SHENNONG_JWT_AUDIENCE=${SHENNONG_JWT_AUDIENCE:-shennong-runtime}
  export SHENNONG_JWT_MAX_TTL_SECONDS=${SHENNONG_JWT_MAX_TTL_SECONDS:-120}
  export SHENNONG_OS_AUTH_COOKIE_NAMES=${SHENNONG_OS_AUTH_COOKIE_NAMES:-shennong_os_session,shennong_os_csrf}
  if [ -z "${SHENNONG_WORKER_PROFILES_JSON:-}" ]; then
    SHENNONG_WORKER_PROFILES_JSON=$(printf '%s' "{\"profiles\":[{\"name\":\"cpu-small\",\"image\":\"$image\",\"kind\":\"batch\",\"max_resources\":{\"cpus\":2.0,\"memory_bytes\":8589934592,\"pids\":256,\"timeout_seconds\":1800,\"tmpfs_bytes\":1073741824,\"max_log_bytes\":8388608,\"max_artifact_bytes\":2147483648,\"max_workspace_bytes\":21474836480}},{\"name\":\"ide-small\",\"image\":\"$image\",\"kind\":\"ide\",\"max_resources\":{\"cpus\":4.0,\"memory_bytes\":17179869184,\"pids\":512,\"timeout_seconds\":28800,\"tmpfs_bytes\":2147483648,\"max_log_bytes\":16777216,\"max_artifact_bytes\":4294967296,\"max_workspace_bytes\":53687091200}}]}")
    export SHENNONG_WORKER_PROFILES_JSON
  fi
fi

exec "$@"
