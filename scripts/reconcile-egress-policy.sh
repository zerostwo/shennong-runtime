#!/usr/bin/env bash
# Reinstalls the nftables policy in the current RootlessKit network namespace
# and publishes a root-owned attestation consumed by Runtime before launches.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "egress policy reconciliation must run as root" >&2
  exit 64
fi

ROOTLESS_UID="${1:-}"
if [[ ! "${ROOTLESS_UID}" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: reconcile-egress-policy.sh ROOTLESS_UID" >&2
  exit 64
fi

JOB_BRIDGE="${SHENNONG_JOB_BRIDGE:-sn-job-egress}"
SESSION_BRIDGE="${SHENNONG_SESSION_BRIDGE:-sn-session}"
RUNTIME_PROXY_V4="${SHENNONG_RUNTIME_PROXY_V4:?set one exact Runtime proxy IPv4 /32}"
ROOTLESSKIT_STATE_DIR="${SHENNONG_ROOTLESSKIT_STATE_DIR:-/run/user/${ROOTLESS_UID}/shennong-runtime-rootlesskit}"
POLICY_STATE_DIR="${SHENNONG_EGRESS_POLICY_STATE_DIR:-/run/shennong-runtime-egress}"
POLICY_INSTALLER="${SHENNONG_POLICY_INSTALLER:-/usr/local/libexec/shennong-runtime/install-egress-policy.sh}"
WAIT_SECONDS="${SHENNONG_POLICY_WAIT_SECONDS:-60}"
CHILD_PID_FILE="${ROOTLESSKIT_STATE_DIR}/child_pid"
ATTESTATION_FILE="${POLICY_STATE_DIR}/policy-${ROOTLESS_UID}.ready"

for command in install ip mktemp mv nft nsenter python3 stat; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "missing prerequisite: ${command}" >&2
    exit 69
  fi
done
if [[ ! -x "${POLICY_INSTALLER}" ]]; then
  echo "policy installer is not executable: ${POLICY_INSTALLER}" >&2
  exit 69
fi
if [[ ! "${WAIT_SECONDS}" =~ ^[1-9][0-9]*$ ]] || (( WAIT_SECONDS > 300 )); then
  echo "SHENNONG_POLICY_WAIT_SECONDS must be between 1 and 300" >&2
  exit 64
fi
for interface in "${JOB_BRIDGE}" "${SESSION_BRIDGE}"; do
  if [[ ! "${interface}" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
    echo "invalid bridge interface: ${interface}" >&2
    exit 64
  fi
done
if [[ "${JOB_BRIDGE}" == "${SESSION_BRIDGE}" ]]; then
  echo "Job and Session bridges must differ" >&2
  exit 64
fi
if ! python3 -c 'import ipaddress,sys
network=ipaddress.ip_network(sys.argv[1], strict=True)
raise SystemExit(0 if network.version == 4 and network.prefixlen == 32 else 1)' \
  "${RUNTIME_PROXY_V4}"; then
  echo "SHENNONG_RUNTIME_PROXY_V4 must be one exact IPv4 /32" >&2
  exit 64
fi

install -d --owner=root --group=root --mode=0755 "${POLICY_STATE_DIR}"
# This removal is the fail-closed transition. Runtime refuses new Job/Session
# launches until this invocation installs and attests the current namespace.
rm -f -- "${ATTESTATION_FILE}"
temporary_attestation=""
cleanup() {
  if [[ -n "${temporary_attestation}" ]]; then
    rm -f -- "${temporary_attestation}"
  fi
  rm -f -- "${ATTESTATION_FILE}"
}
trap cleanup ERR
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

netns_pid=""
netns_inode=""
for ((attempt = 0; attempt < WAIT_SECONDS * 10; attempt++)); do
  candidate="$(tr -d '[:space:]' < "${CHILD_PID_FILE}" 2>/dev/null || true)"
  if [[ "${candidate}" =~ ^[1-9][0-9]*$ ]] \
    && [[ -e "/proc/${candidate}/ns/net" ]] \
    && nsenter --target "${candidate}" --net ip link show dev "${JOB_BRIDGE}" >/dev/null 2>&1 \
    && nsenter --target "${candidate}" --net ip link show dev "${SESSION_BRIDGE}" >/dev/null 2>&1; then
    netns_pid="${candidate}"
    netns_inode="$(stat --dereference --format=%i "/proc/${candidate}/ns/net")"
    break
  fi
  sleep 0.1
done
if [[ -z "${netns_pid}" || ! "${netns_inode}" =~ ^[1-9][0-9]*$ ]]; then
  echo "RootlessKit namespace and both executor bridges were not ready within ${WAIT_SECONDS}s" >&2
  exit 69
fi

SHENNONG_NETNS_PID="${netns_pid}" \
SHENNONG_JOB_BRIDGE="${JOB_BRIDGE}" \
SHENNONG_SESSION_BRIDGE="${SESSION_BRIDGE}" \
SHENNONG_RUNTIME_PROXY_V4="${RUNTIME_PROXY_V4}" \
  "${POLICY_INSTALLER}"

pid_after="$(tr -d '[:space:]' < "${CHILD_PID_FILE}" 2>/dev/null || true)"
inode_after="$(stat --dereference --format=%i "/proc/${netns_pid}/ns/net" 2>/dev/null || true)"
if [[ "${pid_after}" != "${netns_pid}" || "${inode_after}" != "${netns_inode}" ]]; then
  echo "RootlessKit namespace changed while installing the egress policy" >&2
  exit 75
fi
nsenter --target "${netns_pid}" --net nft list table inet shennong_runtime >/dev/null

temporary_attestation="$(mktemp "${POLICY_STATE_DIR}/.policy-${ROOTLESS_UID}.XXXXXX")"
printf '{"version":1,"rootless_uid":%s,"netns_pid":%s,"netns_inode":%s,"job_bridge":"%s","session_bridge":"%s","runtime_proxy_v4":"%s"}\n' \
  "${ROOTLESS_UID}" "${netns_pid}" "${netns_inode}" \
  "${JOB_BRIDGE}" "${SESSION_BRIDGE}" "${RUNTIME_PROXY_V4}" \
  > "${temporary_attestation}"
chown root:root "${temporary_attestation}"
chmod 0644 "${temporary_attestation}"
mv --force -- "${temporary_attestation}" "${ATTESTATION_FILE}"
temporary_attestation=""
trap - ERR INT TERM

echo "attested shennong_runtime nftables policy for RootlessKit PID ${netns_pid}"
