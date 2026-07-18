#!/usr/bin/env bash
# Installs a dedicated user-level Docker daemon. Run as the dedicated executor
# account, never as root and never as the account that owns the control daemon.
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  echo "run this installer as the dedicated non-root executor user" >&2
  exit 64
fi

for command in dockerd-rootless.sh newuidmap newgidmap systemctl; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "missing prerequisite: ${command}" >&2
    exit 69
  fi
done

if [[ "$(stat --file-system --format=%T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
  echo "cgroup v2 is required for enforceable rootless resource limits" >&2
  exit 69
fi

current_user="$(id --user --name)"
if ! grep -q "^${current_user}:" /etc/subuid || ! grep -q "^${current_user}:" /etc/subgid; then
  echo "${current_user} requires subordinate UID/GID ranges in /etc/subuid and /etc/subgid" >&2
  exit 69
fi

config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"
runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id --user)}"
unit_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deployments/systemd/shennong-runtime-docker.service"
unit_target="${config_home}/systemd/user/shennong-runtime-docker.service"

install -D --mode=0600 "${unit_source}" "${unit_target}"
systemctl --user daemon-reload
systemctl --user enable --now shennong-runtime-docker.service

socket="${runtime_dir}/shennong-runtime-docker/docker.sock"
for _ in $(seq 1 30); do
  [[ -S "${socket}" ]] && break
  sleep 1
done
if [[ ! -S "${socket}" ]]; then
  echo "rootless Docker socket was not created: ${socket}" >&2
  exit 70
fi

security_options="$(docker --host "unix://${socket}" info --format '{{json .SecurityOptions}}')"
if [[ "${security_options}" != *rootless* ]]; then
  echo "installed daemon does not report rootless mode" >&2
  exit 70
fi

echo "rootless executor socket: ${socket}"
echo "for boot persistence, an administrator should run: loginctl enable-linger ${current_user}"
echo "next: DOCKER_HOST=unix://${socket} bash scripts/bootstrap-rootless-executor.sh"
