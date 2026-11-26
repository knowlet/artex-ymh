#!/usr/bin/env python3
"""Boot the real packaged ARTEX image against a disposable PostgreSQL container.

The private Docker network has no external route, and no ports are published.
No model credentials, tasks, scanners or user data are used. All resource names
are unique and cleanup only removes resources created by this invocation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def docker(*args: str, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True, timeout=timeout)


def wait_for(description, probe, timeout=120):
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            if result := probe():
                return result
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {description}: {last_error}")


def readiness(container):
    result = docker("exec", container, "curl", "--silent", "--show-error", "--max-time", "5",
                    "--unix-socket", "/tmp/artex-ota-health.sock", "--write-out", "\n%{http_code}",
                    "http://localhost/health", timeout=10)
    body, status = result.stdout.rsplit("\n", 1)
    return int(status), json.loads(body)


def run(image: str, postgres_image: str) -> None:
    docker("info", timeout=15)
    suffix = uuid.uuid4().hex[:14]
    prefix = f"artex-ota-smoke-{suffix}"
    containers, volumes = [], []
    network = None
    with tempfile.TemporaryDirectory(prefix=prefix + "-") as directory:
        state = Path(directory)
        marker = state / "maintenance.json"
        marker.write_text('{"job_id":"packaged-image-smoke"}\n')
        try:
            network = docker("network", "create", "--internal", "--label", "io.artex.ota.fixture=true", prefix).stdout.strip()
            for name in (prefix + "-pgdata", prefix + "-data"):
                volumes.append(docker("volume", "create", "--label", "io.artex.ota.fixture=true", name).stdout.strip())
            # Images are pulled before the isolated containers start. Only these
            # known PostgreSQL test images and the explicitly supplied app image
            # are used; no run step can reach an external target or model.
            docker("pull", postgres_image, timeout=180)
            postgres = docker("run", "-d", "--name", prefix + "-postgres", "--network", network,
                              "--network-alias", "postgres", "--label", "io.artex.ota.fixture=true",
                              "-e", "POSTGRES_USER=artex", "-e", "POSTGRES_PASSWORD=ota-smoke-fixture",
                              "-e", "POSTGRES_DB=artex", "-v", volumes[0] + ":/var/lib/postgresql/data",
                              postgres_image).stdout.strip()
            containers.append(postgres)
            wait_for("PostgreSQL", lambda: docker("exec", postgres, "pg_isready", "-h", "127.0.0.1",
                                                     "-U", "artex", "-d", "artex", check=False).returncode == 0)
            app = docker("run", "-d", "--name", prefix + "-app", "--network", network,
                         "--label", "io.artex.ota.fixture=true", "-v", volumes[1] + ":/app/data",
                         "--mount", f"type=bind,src={state},dst=/run/artex-updater/state,readonly",
                         "-e", "ARTEX_PG_DSN=postgres://artex:ota-smoke-fixture@postgres:5432/artex?sslmode=disable",
                         "-e", "ARTEX_OTA_SOCKET=/run/artex-updater/updater.sock",
                         "-e", "ARTEX_OTA_STATE_DIR=/run/artex-updater/state",
                         "-e", "ARTEX_OTA_HEALTH_SOCKET=/tmp/artex-ota-health.sock", image).stdout.strip()
            containers.append(app)

            def healthy(maintenance):
                status, body = readiness(app)
                return (status == 200 and body.get("ready") is True and body.get("ota_protocol") == 1
                        and body.get("maintenance") is maintenance and body.get("idle") is True
                        and body.get("data_dir") == "/app/data" and body.get("gate_enabled") is True)

            wait_for("packaged ARTEX startup, database connection and OTA maintenance", lambda: healthy(True))
            mode = docker("exec", app, "stat", "-c", "%a", "/tmp/artex-ota-health.sock").stdout.strip()
            if mode != "600":
                raise RuntimeError(f"readiness socket mode must be 600, got {mode}")
            marker.unlink()
            wait_for("maintenance release", lambda: healthy(False), timeout=15)
            marker.write_text('{"job_id":"packaged-image-smoke"}\n')
            wait_for("maintenance re-entry", lambda: healthy(True), timeout=15)

            docker("stop", "--time", "10", postgres, timeout=20)
            def unavailable():
                status, body = readiness(app)
                return status == 503 and body.get("ready") is False and body.get("maintenance") is True
            wait_for("readiness failure when PostgreSQL is unavailable", unavailable, timeout=20)
            docker("start", postgres)
            wait_for("readiness recovery after PostgreSQL returns", lambda: healthy(True))
            print(f"Packaged ARTEX + {postgres_image}: startup, 0600 Unix socket, maintenance gate, DB failure/recovery passed")
        except Exception:
            for container in containers:
                result = docker("logs", "--tail", "60", container, check=False)
                print(f"Fixture {container[:12]} logs:\n{result.stdout}{result.stderr}")
            raise
        finally:
            for container in reversed(containers):
                docker("rm", "-f", container, check=False)
            for volume in volumes:
                docker("volume", "rm", volume, check=False)
            if network:
                docker("network", "rm", network, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--postgres-image", choices=("postgres:16-alpine", "postgres:17-alpine"), default="postgres:17-alpine")
    args = parser.parse_args()
    run(args.image, args.postgres_image)
