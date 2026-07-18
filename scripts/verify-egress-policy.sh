#!/usr/bin/env bash
# Destructive scope: creates and removes only three labeled test containers and
# one temporary Docker network on the selected dedicated rootless daemon.
set -euo pipefail

: "${DOCKER_HOST:?set DOCKER_HOST to the dedicated rootless Docker socket}"
: "${SHENNONG_EGRESS_TEST_IMAGE:?set a digest-pinned Python image}"
: "${SHENNONG_RUNTIME_CONTROL_URL:?set the live private Runtime health URL}"

if [[ "${SHENNONG_EGRESS_TEST_IMAGE}" != *@sha256:* ]]; then
  echo "SHENNONG_EGRESS_TEST_IMAGE must be digest-pinned" >&2
  exit 64
fi
case "${DOCKER_HOST}" in
  unix://*) ;;
  *) echo "DOCKER_HOST must be a unix socket" >&2; exit 64 ;;
esac
docker_socket="${DOCKER_HOST#unix://}"
docker_socket_real="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${docker_socket}")"
case "${docker_socket_real}" in
  /var/run/docker.sock|/run/docker.sock)
    echo "refusing the system Docker socket" >&2
    exit 64
    ;;
esac
if [[ ! -S "${docker_socket_real}" ]]; then
  echo "DOCKER_HOST does not resolve to a unix socket" >&2
  exit 64
fi
case "${SHENNONG_RUNTIME_CONTROL_URL}" in
  http://*|https://*) ;;
  *) echo "SHENNONG_RUNTIME_CONTROL_URL must be an HTTP(S) URL" >&2; exit 64 ;;
esac

if ! python3 -c 'import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=3).read(1)' \
  "${SHENNONG_RUNTIME_CONTROL_URL}"; then
  echo "Runtime control URL is not live from the host; refusing a false-positive isolation test" >&2
  exit 69
fi

job_network="${SHENNONG_JOB_EGRESS_NETWORK:-shennong-job-egress}"
session_network="${SHENNONG_SESSION_PROXY_NETWORK:-shennong-session-proxy}"
probe_network="shennong-egress-probe-$$"
job_server_name="shennong-egress-job-server-$$"
session_server_name="shennong-egress-session-server-$$"

cleanup() {
  docker rm --force "${job_server_name}" >/dev/null 2>&1 || true
  docker rm --force "${session_server_name}" >/dev/null 2>&1 || true
  docker network rm "${probe_network}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network inspect "${job_network}" >/dev/null
docker network inspect "${session_network}" >/dev/null
docker network create --driver bridge --label dev.shennong.test=true "${probe_network}" >/dev/null

python_test='import sys,urllib.error,urllib.request
urls=sys.argv[1:]
for url in urls:
    try:
        urllib.request.urlopen(url, timeout=3)
    except urllib.error.HTTPError as error:
        raise SystemExit("destination reachable with HTTP status: " + url + " " + str(error.code)) from error
    except (urllib.error.URLError, TimeoutError, OSError):
        continue
    raise SystemExit("destination unexpectedly reachable: " + url)'

docker run --rm \
  --network "${job_network}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 32 \
  --memory 128m \
  --cpus 0.5 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --entrypoint python3 \
  "${SHENNONG_EGRESS_TEST_IMAGE}" \
  -c 'import urllib.request; urllib.request.urlopen("https://example.com", timeout=10).read(1)' \
  || { echo "public HTTPS egress failed" >&2; exit 1; }

docker run --rm \
  --network "${job_network}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 32 \
  --memory 128m \
  --cpus 0.5 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --entrypoint python3 \
  "${SHENNONG_EGRESS_TEST_IMAGE}" \
  -c "${python_test}" \
  "${SHENNONG_RUNTIME_CONTROL_URL}" \
  http://127.0.0.1:7000 \
  http://10.0.0.1 \
  http://172.16.0.1 \
  http://192.168.0.1 \
  http://169.254.169.254/latest/meta-data/ \
  'http://[::1]:7000' \
  'http://[fc00::1]' \
  'http://[fe80::1]' \
  'http://[ff02::1]' \
  'http://[2001:db8::1]'

# An IDE session is browser-facing data plane only. It must not be able to
# call Runtime's private control address or cloud-instance metadata. This is
# deliberately tested against a live health URL so a policy installed in the
# wrong namespace cannot pass because the destination happened to be absent.
docker run --rm \
  --network "${session_network}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 32 \
  --memory 128m \
  --cpus 0.5 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --entrypoint python3 \
  "${SHENNONG_EGRESS_TEST_IMAGE}" \
  -c "${python_test}" \
  "${SHENNONG_RUNTIME_CONTROL_URL}" \
  http://169.254.169.254/latest/meta-data/ \
  'http://[::1]:7000' \
  'http://[fc00::1]' \
  'http://[fe80::1]' \
  'http://[ff02::1]' \
  'http://[2001:db8::1]'

docker run --detach --rm \
  --name "${job_server_name}" \
  --network "${job_network}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 32 \
  --memory 128m \
  --cpus 0.5 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --entrypoint python3 \
  "${SHENNONG_EGRESS_TEST_IMAGE}" \
  -m http.server 18080 >/dev/null
server_ip="$(docker inspect --format "{{with index .NetworkSettings.Networks \"${job_network}\"}}{{.IPAddress}}{{end}}" "${job_server_name}")"

if docker run --rm \
  --network "${probe_network}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --entrypoint python3 \
  "${SHENNONG_EGRESS_TEST_IMAGE}" \
  -c 'import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=3)' \
  "http://${server_ip}:18080" >/dev/null 2>&1; then
  echo "new inbound connection to a Job container was not blocked" >&2
  exit 1
fi

# The trusted host-network Runtime daemon must retain a usable data path to an
# IDE port that is published only on host loopback.
docker run --detach --rm \
  --name "${session_server_name}" \
  --network "${session_network}" \
  --publish 127.0.0.1::18081 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 32 \
  --memory 128m \
  --cpus 0.5 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --entrypoint python3 \
  "${SHENNONG_EGRESS_TEST_IMAGE}" \
  -m http.server 18081 >/dev/null
loopback_port="$(docker port "${session_server_name}" 18081/tcp | awk -F: '$1 == "127.0.0.1" {print $NF; exit}')"
if [[ ! "${loopback_port}" =~ ^[1-9][0-9]*$ ]]; then
  echo "session fixture did not receive a loopback-only random port" >&2
  exit 1
fi
for _ in $(seq 1 20); do
  if python3 -c 'import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2).read(1)' \
    "http://127.0.0.1:${loopback_port}"; then
    loopback_ok=1
    break
  fi
  sleep 0.1
done
if [[ "${loopback_ok:-0}" != "1" ]]; then
  echo "host Runtime proxy path cannot reach the loopback-only IDE port" >&2
  exit 1
fi

echo "egress verification passed: public HTTPS allowed; Job IPv4/IPv6 private/metadata and new inbound blocked; IDE IPv4/IPv6 control-plane access blocked; host IDE proxy path reachable"
