#!/usr/bin/env bash
# Installs the root-owned systemd path/service pair that restores the nftables
# policy whenever the dedicated RootlessKit namespace changes.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run this installer as root" >&2
  exit 64
fi
for command in getent install mktemp python3 systemctl systemd-tmpfiles; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "missing prerequisite: ${command}" >&2
    exit 69
  fi
done

ROOTLESS_UID="${SHENNONG_EXECUTOR_UID:?set the dedicated rootless executor UID}"
RUNTIME_PROXY_V4="${SHENNONG_RUNTIME_PROXY_V4:?set one exact Runtime proxy IPv4 /32}"
JOB_BRIDGE="${SHENNONG_JOB_BRIDGE:-sn-job-egress}"
SESSION_BRIDGE="${SHENNONG_SESSION_BRIDGE:-sn-session}"
if [[ ! "${ROOTLESS_UID}" =~ ^[1-9][0-9]*$ ]] || ! getent passwd "${ROOTLESS_UID}" >/dev/null; then
  echo "SHENNONG_EXECUTOR_UID must identify an existing non-root account" >&2
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

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
libexec_dir="/usr/local/libexec/shennong-runtime"
config_dir="/etc/shennong-runtime"
state_dir="/run/shennong-runtime-egress"
environment_file="${config_dir}/egress-policy-${ROOTLESS_UID}.env"

install -d --owner=root --group=root --mode=0755 "${libexec_dir}" "${config_dir}" "${state_dir}"
install --owner=root --group=root --mode=0755 \
  "${repository_root}/scripts/install-egress-policy.sh" \
  "${libexec_dir}/install-egress-policy.sh"
install --owner=root --group=root --mode=0755 \
  "${repository_root}/scripts/reconcile-egress-policy.sh" \
  "${libexec_dir}/reconcile-egress-policy.sh"
install --owner=root --group=root --mode=0644 \
  "${repository_root}/deployments/systemd/shennong-runtime-egress-policy@.service" \
  /etc/systemd/system/shennong-runtime-egress-policy@.service
install --owner=root --group=root --mode=0644 \
  "${repository_root}/deployments/systemd/shennong-runtime-egress-policy@.path" \
  /etc/systemd/system/shennong-runtime-egress-policy@.path
install --owner=root --group=root --mode=0644 \
  "${repository_root}/deployments/tmpfiles/shennong-runtime-egress.conf" \
  /etc/tmpfiles.d/shennong-runtime-egress.conf

temporary_environment="$(mktemp "${config_dir}/.egress-policy-${ROOTLESS_UID}.XXXXXX")"
trap 'rm -f -- "${temporary_environment}"' EXIT
printf 'SHENNONG_JOB_BRIDGE=%s\nSHENNONG_SESSION_BRIDGE=%s\nSHENNONG_RUNTIME_PROXY_V4=%s\n' \
  "${JOB_BRIDGE}" "${SESSION_BRIDGE}" "${RUNTIME_PROXY_V4}" \
  > "${temporary_environment}"
chown root:root "${temporary_environment}"
chmod 0600 "${temporary_environment}"
mv --force -- "${temporary_environment}" "${environment_file}"
trap - EXIT

systemd-tmpfiles --create /etc/tmpfiles.d/shennong-runtime-egress.conf
systemctl daemon-reload
systemctl enable --now "shennong-runtime-egress-policy@${ROOTLESS_UID}.path"
systemctl enable --now "shennong-runtime-egress-policy@${ROOTLESS_UID}.service"

echo "egress policy auto-recovery installed for rootless UID ${ROOTLESS_UID}"
echo "attestation: ${state_dir}/policy-${ROOTLESS_UID}.ready"
