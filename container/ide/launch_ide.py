#!/usr/bin/env python3
"""Supervise one loopback-only IDE and its authenticated gateway."""

import os
import signal
import socket
import subprocess
import sys
import time


GATEWAY = "/opt/shennong/bin/shennong-ide-gateway"
RSTUDIO_STATE_DIR = "/tmp/shennong-rstudio"
RSTUDIO_DATABASE_CONFIG = "/opt/shennong/etc/rstudio-database.conf"
WORKSPACE_HOME = "/workspace/.shennong/home"


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def commands(kind: str, proxy_path: str) -> tuple[list[str], str, int]:
    if kind == "rstudio":
        os.makedirs(RSTUDIO_STATE_DIR, mode=0o700, exist_ok=True)
        os.chmod(RSTUDIO_STATE_DIR, 0o700)
        return (
            [
                "/usr/lib/rstudio-server/bin/rserver",
                "--server-daemonize=0",
                "--www-address=127.0.0.1",
                "--www-port=18787",
                "--auth-none=1",
                "--server-user=shennong",
                f"--server-data-dir={RSTUDIO_STATE_DIR}",
                f"--server-pid-file={RSTUDIO_STATE_DIR}/rserver.pid",
                f"--secure-cookie-key-file={RSTUDIO_STATE_DIR}/secure-cookie-key",
                f"--database-config-file={RSTUDIO_DATABASE_CONFIG}",
            ],
            "http://127.0.0.1:18787/",
            18787,
        )
    if kind == "jupyterlab":
        return (
            [
                "jupyter",
                "lab",
                "--ip=127.0.0.1",
                "--port=18888",
                "--ServerApp.port_retries=0",
                "--no-browser",
                "--IdentityProvider.token=",
                "--ServerApp.log_level=WARN",
                f"--ServerApp.base_url={proxy_path}/",
            ],
            "http://127.0.0.1:18888/",
            18888,
        )
    raise RuntimeError("SHENNONG_IDE_KIND must be rstudio or jupyterlab")


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def wait_until_ready(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status = process.poll()
        if status is not None:
            raise RuntimeError(f"IDE exited before readiness with code {status}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("IDE did not become ready within 60 seconds")


def main() -> int:
    kind = required("SHENNONG_IDE_KIND")
    proxy_path = required("SHENNONG_IDE_PROXY_PATH")
    required("SHENNONG_IDE_GATEWAY_SECRET_SHA256")
    required("SHENNONG_IDE_GATEWAY_LISTEN")
    os.makedirs(WORKSPACE_HOME, mode=0o700, exist_ok=True)
    os.chmod(WORKSPACE_HOME, 0o700)
    ide_command, upstream, ide_port = commands(kind, proxy_path)
    ide_env = os.environ.copy()
    # RStudio's auth-none flow signs core::system::username(), which reads
    # USER rather than resolving the effective uid. Force the fixed container
    # identity so it cannot issue an invalid empty-user authentication cookie.
    ide_env.update(
        {
            "HOME": WORKSPACE_HOME,
            "USER": "shennong",
            "LOGNAME": "shennong",
        }
    )
    for name in (
        "SHENNONG_IDE_GATEWAY_SECRET_SHA256",
        "SHENNONG_IDE_GATEWAY_LISTEN",
        "SHENNONG_IDE_GATEWAY_UPSTREAM",
    ):
        ide_env.pop(name, None)
    gateway_env = os.environ.copy()
    gateway_env["SHENNONG_IDE_GATEWAY_UPSTREAM"] = upstream
    gateway_env["SHENNONG_IDE_GATEWAY_PROXY_PATH"] = proxy_path
    # RStudio uses the gateway's trusted X-RStudio-Root-Path header; do not
    # also set www-root-path because Posit documents these as alternatives.
    # Jupyter owns its prefix through ServerApp.base_url and receives it intact.
    gateway_env["SHENNONG_IDE_GATEWAY_STRIP_PREFIX"] = (
        "true" if kind == "rstudio" else "false"
    )

    ide = subprocess.Popen(ide_command, env=ide_env, close_fds=True)
    try:
        wait_until_ready(ide, ide_port)
    except Exception:
        terminate(ide)
        raise
    try:
        gateway = subprocess.Popen([GATEWAY], env=gateway_env, close_fds=True)
    except Exception:
        terminate(ide)
        raise
    children = [ide, gateway]

    def handle_signal(signum: int, _frame: object) -> None:
        for child in children:
            if child.poll() is None:
                child.send_signal(signum)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        while True:
            for child in children:
                status = child.poll()
                if status is not None:
                    return status if status != 0 else 1
            time.sleep(0.1)
    finally:
        for child in children:
            terminate(child)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"IDE supervisor failed: {error}", file=sys.stderr)
        raise SystemExit(1)
