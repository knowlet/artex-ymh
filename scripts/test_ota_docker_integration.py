#!/usr/bin/env python3
"""Disposable Docker/Compose rehearsal for ARTEX OTA.

This suite uses a tiny local HTTP fixture, a real PostgreSQL container, and the
production Docker backend.  It never publishes an image, invokes an LLM, or
touches an existing deployment.  Registry/signature transport is supplied by the
test harness; there is no production signature-bypass option.

Run explicitly with ARTEX_REQUIRE_DOCKER_OTA=1.  That mode fails (rather than
skipping) if Docker or Compose is unavailable.  Ordinary offline unit-test
discovery leaves this slower, network-dependent suite disabled.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

import docker_ota as ota


REQUIRED = os.environ.get("ARTEX_REQUIRE_DOCKER_OTA") == "1"


FIXTURE_APP = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

if len(sys.argv) > 1 and sys.argv[1] == "doctor":
    # The host backend independently checks and dumps the real database.  This
    # fixture supplies only the application process/HTTP half of readiness.
    sys.exit(0)

# Match the real application's graceful container shutdown. Python as PID 1
# otherwise waits for Docker's forced-stop deadline on every replacement.
signal.signal(signal.SIGTERM, lambda *_args: sys.exit(0))

data = Path("/app/data")
data.mkdir(parents=True, exist_ok=True)
(data / ("boot-" + os.environ["FIXTURE_VERSION"])).write_text("booted\n")
key = Path("/app/jwt.key")
if not key.exists():
    key.write_text("fixture-authentication-key-32-characters\n")
    key.chmod(0o600)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if os.environ.get("FIXTURE_UNHEALTHY") == "1":
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"unhealthy fixture")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "service": "artex",
            "version": os.environ["FIXTURE_VERSION"], "ready": True,
            "maintenance": Path("/run/artex-ota-state/maintenance.json").exists(),
            "idle": True, "ota_protocol": 1, "data_dir": "/app/data",
            "gate_enabled": False}).encode())

    def log_message(self, *_args):
        pass

health_path = Path(os.environ["ARTEX_OTA_HEALTH_SOCKET"])
health_path.unlink(missing_ok=True)
health = socketserver.UnixStreamServer(str(health_path), Handler)
threading.Thread(target=health.serve_forever, daemon=True).start()
HTTPServer(("0.0.0.0", 8787), Handler).serve_forever()
'''


class DockerFixture:
    """All resources have a random project/tag and are removed by this owner."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="artex-ota-rehearsal-")
        self.root = Path(self.temp.name)
        self.project = "artex-ota-test-" + uuid.uuid4().hex[:12]
        self.compose_file = self.root / "compose.json"
        self.state = self.root / "updater-state"
        self.socket_dir = self.root / "updater-run"
        self.data = self.root / "data"
        self.images: dict[str, str] = {}
        self.tags: list[str] = []
        for directory in (self.state, self.socket_dir, self.data, self.root / "skills"):
            directory.mkdir(mode=0o700)
        (self.state / "public").mkdir(mode=0o755)
        (self.root / ".env").write_text("")
        (self.data / "operator-sentinel.txt").write_text("preserve local data\n")

    @staticmethod
    def run(*args: str, input: bytes | None = None, timeout: int = 180) -> str:
        result = subprocess.run(args, input=input, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
        if result.returncode:
            # Fixtures have no real credentials.  Keep diagnostics bounded so a
            # failed CI assertion does not bury the primary error in build logs.
            raise RuntimeError(f"{args[0]} {args[1:3]} failed ({result.returncode}): "
                               + result.stderr.decode(errors="replace")[-6000:])
        return result.stdout.decode()

    def docker(self, *args: str, timeout: int = 180) -> str:
        return self.run("docker", *args, timeout=timeout)

    def compose(self, *args: str, timeout: int = 180) -> str:
        return self.docker("compose", "--project-name", self.project,
                           "--project-directory", str(self.root), "--env-file",
                           str(self.root / ".env"), "-f", str(self.compose_file),
                           *args, timeout=timeout)

    def build_image(self, version: str, *, schema: str, unhealthy: bool = False) -> str:
        build = self.root / ("build-" + version)
        build.mkdir()
        (build / "artex").write_text(FIXTURE_APP)
        (build / "Dockerfile").write_text(
            "FROM python:3.12-slim-bookworm\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends curl "
            "&& rm -rf /var/lib/apt/lists/*\n"
            "WORKDIR /app\n"
            "COPY artex /app/artex\n"
            "RUN cp /app/artex /app/start.sh && chmod 755 /app/artex /app/start.sh\n"
            'LABEL io.artex.ota.protocol="1"\n'
            f'LABEL io.artex.ota.schema="{schema}"\n'
            f'LABEL org.opencontainers.image.revision="{version[0] * 40}"\n'
            'LABEL org.opencontainers.image.source="https://github.com/knowlet/artex-ymh"\n'
            f"ENV FIXTURE_VERSION={version} FIXTURE_UNHEALTHY={int(unhealthy)}\n"
            'ENTRYPOINT ["/app/start.sh"]\n'
        )
        tag = f"{self.project}:{version}"
        self.docker("build", "--quiet", "-t", tag, str(build), timeout=600)
        image_id = self.docker("image", "inspect", "--format", "{{.Id}}", tag).strip()
        self.images[version] = image_id
        self.tags.append(tag)
        return image_id

    def configure(self, image_id: str):
        self.compose_file.write_text(json.dumps({
            "services": {
                "postgres": {
                    "image": "postgres:16-alpine",
                    "environment": {"POSTGRES_USER": "artex", "POSTGRES_PASSWORD": "fixture-$$only",
                                    "POSTGRES_DB": "artex"},
                    "volumes": ["pgdata:/var/lib/postgresql/data"],
                    "healthcheck": {"test": ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U artex -d artex"],
                                    "interval": "1s", "timeout": "3s", "retries": 60},
                },
                "artex": {
                    "image": image_id,
                    # Preserve the existing source-build mode as well. OTA
                    # snapshots must not rebuild or lose config-hash identity
                    # when this original Compose build section is still here.
                    "build": {"context": str(self.root / "build-a-old")},
                    "pull_policy": "never",
                    "environment": {
                        "ARTEX_PG_DSN": "postgres://artex:fixture-%24only@postgres:5432/artex?sslmode=disable",
                        "ARTEX_GATE": "off",
                        "ARTEX_OTA_STATE_DIR": "/run/artex-ota-state",
                        "ARTEX_OTA_SOCKET": "/run/artex-updater/api.sock",
                        "ARTEX_OTA_HEALTH_SOCKET": ota.HEALTH_SOCKET,
                    },
                    "depends_on": {"postgres": {"condition": "service_healthy"}},
                    "volumes": [f"{self.data}:/app/data", f"{self.root / 'skills'}:/app/skills",
                                f"{self.state / 'public'}:/run/artex-ota-state:ro",
                                f"{self.socket_dir}:/run/artex-updater:ro"],
                },
            },
            "volumes": {"pgdata": {}},
            "networks": {"default": {"internal": True}},
        }))

    def start(self):
        self.compose("up", "-d", "--wait", "--wait-timeout", "90", timeout=180)
        self.sql("CREATE TABLE ota_sentinel(id integer PRIMARY KEY, value text NOT NULL); "
                 "INSERT INTO ota_sentinel VALUES (1, 'preserve PostgreSQL rows');")

    def container_id(self, service: str) -> str:
        value = self.compose("ps", "--all", "--quiet", service).strip().splitlines()
        if len(value) != 1:
            raise AssertionError(f"expected exactly one {service} container, got {value}")
        return value[0]

    def sql(self, statement: str) -> str:
        return self.docker("exec", self.container_id("postgres"), "psql", "-X", "-qAt",
                           "-v", "ON_ERROR_STOP=1", "-U", "artex", "-d", "artex", "-c", statement).strip()

    def current_image(self) -> str:
        return self.docker("inspect", "--format", "{{.Image}}", self.container_id("artex")).strip()

    def assert_preserved(self, testcase: unittest.TestCase, postgres_id: str):
        testcase.assertEqual(self.container_id("postgres"), postgres_id,
                             "OTA must not replace PostgreSQL")
        testcase.assertEqual(self.sql("SELECT value FROM ota_sentinel WHERE id=1"),
                             "preserve PostgreSQL rows")
        testcase.assertEqual((self.data / "operator-sentinel.txt").read_text(), "preserve local data\n")

    def close(self):
        try:
            if self.compose_file.exists():
                self.compose("down", "--volumes", "--remove-orphans", timeout=90)
        finally:
            for tag in self.tags:
                subprocess.run(["docker", "image", "rm", tag], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30, check=False)
            self.temp.cleanup()


def require_docker():
    if not REQUIRED:
        raise unittest.SkipTest("set ARTEX_REQUIRE_DOCKER_OTA=1 for the disposable Docker rehearsal")
    if not shutil.which("docker"):
        raise RuntimeError("ARTEX_REQUIRE_DOCKER_OTA=1 but Docker CLI is unavailable")
    DockerFixture.run("docker", "info", "--format", "{{.ID}}", timeout=15)
    DockerFixture.run("docker", "compose", "version", "--short", timeout=15)


class FixtureRegistry:
    """Finite in-memory registry metadata; signatures are tested separately."""

    def __init__(self, images):
        self.images = images
        self.target = "b-good"

    def resolve(self, channel):
        if channel not in ota.CHANNELS:
            raise ota.OTAError("invalid fixture channel")
        schema = "2" * 64 if self.target == "d-schema-failure" else "1" * 64
        digest = self.images[self.target]
        return {"image": ota.REPOSITORY + "@" + digest, "digest": digest,
                "revision": self.target[0] * 40, "schema": schema, "channel": channel}


class FixtureBackend(ota.DockerBackend):
    """Only registry delivery differs; Docker mutation and backups are real."""

    def __init__(self, config, images):
        super().__init__(config)
        self.images = {ota.REPOSITORY + "@" + value: value for value in images.values()}

    def ensure_image(self, plan):
        # The fixture images were just built by this test. Production callers
        # cannot choose this adapter or substitute an image through the API.
        image = self.images[plan["image"]]
        info = self.image_info(image)
        if info["Config"]["Labels"]["io.artex.ota.schema"] != plan["schema"]:
            raise AssertionError("fixture image/schema disagreement")
        return image


class DockerRehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_docker()

    def setUp(self):
        self.fixture = DockerFixture()
        self.addCleanup(self.cleanup_fixture)
        self.fixture.build_image("a-old", schema="1" * 64)
        self.fixture.build_image("b-good", schema="1" * 64)
        self.fixture.build_image("c-unhealthy", schema="1" * 64, unhealthy=True)
        self.fixture.build_image("d-schema-failure", schema="2" * 64, unhealthy=True)
        self.fixture.configure(self.fixture.images["a-old"])
        self.fixture.start()
        self.pg_id = self.fixture.container_id("postgres")
        self.config = ota.Config(
            project_dir=self.fixture.root,
            project_name=self.fixture.project,
            compose_files=[self.fixture.compose_file],
            state_dir=self.fixture.state,
            socket_path=self.fixture.socket_dir / "api.sock",
            env_file=self.fixture.root / ".env",
            docker=shutil.which("docker"),
            health_timeout=10,
            command_timeout=90,
            min_free_bytes=1,
        )
        self.registry = FixtureRegistry(self.fixture.images)
        self.backend = FixtureBackend(self.config, self.fixture.images)
        self.verified = []
        self.updater = ota.Updater(self.config, backend=self.backend, registry=self.registry,
                                   verifier=self.verified.append)

    def cleanup_fixture(self):
        # The production Runner suppresses child stderr because deployments can
        # contain secrets. These disposable fixtures contain only test values;
        # preserve bounded diagnostics before their containers are removed.
        result = self._outcome.result
        if any(test is self for test, _error in result.failures + result.errors):
            print(f"\nFixture diagnostics for {self.id()}:", file=sys.stderr)
            probes = [lambda: self.fixture.compose("ps", "-a", "--format", "json"),
                      lambda: self.fixture.compose("logs", "--no-color", "--tail", "35", "artex", "postgres")]
            if hasattr(self, "backend"):
                probes.append(lambda: self.backend.compose("config", "--hash", "artex").decode())
            for probe in probes:
                try:
                    print(probe()[-12000:], file=sys.stderr)
                except Exception as error:
                    print(f"Fixture diagnostics unavailable: {error}", file=sys.stderr)
        self.fixture.close()

    def wait_job(self):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            result = self.updater.status()
            if not result.get("active"):
                return result
            time.sleep(0.2)
        self.fail(f"updater did not finish: {self.updater.status()}")

    def apply(self, target):
        self.registry.target = target
        plan = self.updater.check("main")
        self.updater.submit(plan["plan_id"])
        return self.wait_job()

    def test_update_then_manual_rollback_preserves_database_data_and_keys(self):
        before_key = self.fixture.docker("exec", self.fixture.container_id("artex"), "cat", "/app/jwt.key")
        completed = self.apply("b-good")
        self.assertEqual(completed["state"], "completed", completed)
        self.assertEqual(self.fixture.current_image(), self.fixture.images["b-good"])
        self.assertFalse(self.config.marker.exists())
        self.assertTrue(completed["rollback_available"])
        self.fixture.assert_preserved(self, self.pg_id)
        backup = Path(completed["backup"])
        self.assertGreater((backup / "postgres.dump").stat().st_size, 0)
        self.assertGreater((backup / "data.tar").stat().st_size, 0)
        self.assertEqual(self.fixture.docker("exec", self.fixture.container_id("artex"), "cat", "/app/jwt.key"),
                         before_key)
        self.assertEqual(len(self.verified), 2, "check and apply both verify the pinned image")
        self.updater.submit(operation="rollback")
        rolled_back = self.wait_job()
        self.assertEqual(rolled_back["state"], "rolled_back", rolled_back)
        self.assertEqual(self.fixture.current_image(), self.fixture.images["a-old"])
        self.assertFalse(self.config.marker.exists())
        self.fixture.assert_preserved(self, self.pg_id)

    def test_unhealthy_candidate_rolls_back_only_with_matching_fingerprint(self):
        result = self.apply("c-unhealthy")
        self.assertEqual(result["state"], "rolled_back", result)
        self.assertEqual(self.fixture.current_image(), self.fixture.images["a-old"])
        self.assertFalse(self.config.marker.exists())
        self.fixture.assert_preserved(self, self.pg_id)

    def test_changed_schema_failure_remains_closed_for_recovery(self):
        result = self.apply("d-schema-failure")
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertFalse(result["rollback_available"])
        self.assertTrue(self.config.marker.exists())
        self.assertEqual(self.fixture.current_image(), self.fixture.images["d-schema-failure"])
        self.fixture.assert_preserved(self, self.pg_id)
        with self.assertRaises(ota.OTAError):
            self.updater.submit(operation="rollback")
        restarted = ota.Updater(self.config, backend=self.backend, registry=self.registry,
                                verifier=self.verified.append)
        self.assertEqual(restarted.status()["state"], "recovery_required")
        self.assertTrue(self.config.marker.exists())

    def test_backup_failure_restarts_exact_previous_container(self):
        previous = self.fixture.container_id("artex")
        def fail_backup(_record, _directory):
            raise ota.OTAError("deliberate disposable backup failure")
        self.backend.backup = fail_backup
        result = self.apply("b-good")
        self.assertEqual(result["state"], "rolled_back", result)
        self.assertEqual(self.fixture.container_id("artex"), previous)
        self.assertEqual(self.fixture.current_image(), self.fixture.images["a-old"])
        self.assertFalse(self.config.marker.exists())
        self.fixture.assert_preserved(self, self.pg_id)

    def test_changed_data_mount_rejected_before_stopping_original(self):
        previous = self.fixture.container_id("artex")
        self.registry.target = "b-good"
        plan = self.updater.check("main")
        config = json.loads(self.fixture.compose_file.read_text())
        replacement = self.fixture.root / "different-data"
        replacement.mkdir()
        config["services"]["artex"]["volumes"][0] = f"{replacement}:/app/data"
        self.fixture.compose_file.write_text(json.dumps(config))
        self.updater.submit(plan["plan_id"])
        result = self.wait_job()
        self.assertEqual(result["state"], "failed", result)
        self.assertEqual(self.fixture.container_id("artex"), previous)
        self.assertEqual(self.fixture.docker("inspect", "--format", "{{.State.Running}}", previous).strip(), "true")
        self.assertFalse(self.config.marker.exists())
        self.assertFalse(list(replacement.iterdir()))
        self.fixture.assert_preserved(self, self.pg_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
