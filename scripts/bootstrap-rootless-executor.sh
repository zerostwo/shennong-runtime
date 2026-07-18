#!/usr/bin/env bash
set -euo pipefail

: "${DOCKER_HOST:?set DOCKER_HOST to the dedicated rootless unix socket}"

case "${DOCKER_HOST}" in
  unix:///var/run/docker.sock|unix:///run/docker.sock)
    echo "refusing the system Docker socket" >&2
    exit 64
    ;;
  unix://*) ;;
  *)
    echo "DOCKER_HOST must be a rootless unix socket" >&2
    exit 64
    ;;
esac

if ! docker info --format '{{json .SecurityOptions}}' | grep -q 'rootless'; then
  echo "the selected Docker daemon does not report rootless security mode" >&2
  exit 69
fi

create_network() {
  local name="$1"
  local subnet="$2"
  local bridge="$3"
  if docker network inspect "${name}" >/dev/null 2>&1; then
    local actual
    actual="$(docker network inspect --format '{{.Driver}}|{{.Scope}}|{{index .Options "com.docker.network.bridge.name"}}|{{index .Labels "dev.shennong.managed"}}|{{index .Labels "dev.shennong.network-policy"}}|{{(index .IPAM.Config 0).Subnet}}' "${name}")"
    if [[ "${actual}" != "bridge|local|${bridge}|true|internet-only|${subnet}" ]]; then
      echo "existing Docker network ${name} is not the expected managed bridge ${bridge} (${subnet})" >&2
      exit 69
    fi
    return
  fi
  docker network create \
    --driver bridge \
    --subnet "${subnet}" \
    --opt "com.docker.network.bridge.name=${bridge}" \
    --label dev.shennong.managed=true \
    --label dev.shennong.network-policy=internet-only \
    "${name}" >/dev/null
}

create_network "${SHENNONG_JOB_EGRESS_NETWORK:-shennong-job-egress}" \
  "${SHENNONG_JOB_SUBNET:-10.251.0.0/24}" \
  "${SHENNONG_JOB_BRIDGE:-sn-job-egress}"
create_network "${SHENNONG_SESSION_PROXY_NETWORK:-shennong-session-proxy}" \
  "${SHENNONG_SESSION_SUBNET:-10.252.0.0/24}" \
  "${SHENNONG_SESSION_BRIDGE:-sn-session}"

echo "rootless executor networks are ready"
