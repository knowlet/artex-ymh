#!/usr/bin/env python3
"""ARTEX's opt-in host updater. No shell, arbitrary image, or Docker API proxy.

The HTTP API is reachable only over a locally provisioned Unix socket. The
authenticated ARTEX backend owns workload admission; this process owns Docker,
durable maintenance state, backups, and the image trust policy.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime as dt
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import uuid

REPOSITORY = "ghcr.io/knowlet/artex-ymh"
SOURCE = "https://github.com/knowlet/artex-ymh"
IDENTITY = SOURCE + "/.github/workflows/docker-ota.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
CHANNELS = {"stable", "nightly", "main"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
SCHEMA = re.compile(r"[0-9a-f]{64}\Z")
TERMINAL = {"idle", "completed", "rolled_back", "failed", "recovery_required"}
HEALTH_SOCKET = "/tmp/artex-ota-health.sock"
MAX_JSON = 2 * 1024 * 1024


class OTAError(Exception):
    """A deliberately non-sensitive, operator-facing failure."""


def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def atomic_json(path: Path, value, mode=0o600):
    """Replace, fsync the file AND parent; never follow a preexisting symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".ota-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as out:
            out.write(canonical(value) + b"\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_json(path: Path):
    with path.open("rb") as source:
        raw = source.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise OTAError("JSON document exceeds the updater limit")
    return json.loads(raw)


def absolute(value, field):
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise OTAError(f"{field} must be an absolute path")
    return Path(value)


@dataclasses.dataclass
class Config:
    project_dir: Path
    project_name: str
    compose_files: list[Path]
    state_dir: Path
    socket_path: Path
    env_file: Path | None = None
    docker: str = "/usr/bin/docker"
    docker_socket: str = "/var/run/docker.sock"
    cosign: str = "/usr/local/bin/cosign"
    health_timeout: int = 180
    command_timeout: int = 600
    min_free_bytes: int = 2 * 1024**3

    @classmethod
    def load(cls, path):
        p = Path(path)
        s = p.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_mode & 0o022 or s.st_uid != os.geteuid():
            raise OTAError("updater configuration must be a regular file without group/world write access")
        raw = read_json(p)
        if set(raw) - {f.name for f in dataclasses.fields(cls)}:
            raise OTAError("unknown updater configuration field")
        for field in ("project_dir", "state_dir", "socket_path"):
            raw[field] = absolute(raw.get(field), field)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", raw.get("project_name", "")):
            raise OTAError("set the existing Compose project_name explicitly")
        files = raw.get("compose_files")
        if not isinstance(files, list) or not 1 <= len(files) <= 16:
            raise OTAError("compose_files must contain the ordered deployment files")
        raw["compose_files"] = [absolute(x, "compose_files") for x in files]
        if raw.get("env_file"):
            raw["env_file"] = absolute(raw["env_file"], "env_file")
        for field in ("docker", "cosign", "docker_socket"):
            if field in raw:
                absolute(raw[field], field)
        for field in ("health_timeout", "command_timeout", "min_free_bytes"):
            if field in raw and (type(raw[field]) is not int or raw[field] <= 0):
                raise OTAError(f"{field} must be a positive integer")
        return cls(**raw)

    @property
    def public_dir(self):
        return self.state_dir / "public"

    @property
    def marker(self):
        return self.public_dir / "maintenance.json"


class Runner:
    def __call__(self, args, *, timeout=600, output=None, input_data=None, input_file=None):
        # Child output can contain registry credentials, DSNs or database rows.
        # It never enters HTTP errors, journal messages, or the service log.
        with tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as captured:
            try:
                result = subprocess.run(args, input=input_data, stdin=input_file, stdout=output or captured,
                                        stderr=errors, timeout=timeout, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise OTAError("host operation failed or timed out; inspect the host prerequisites") from exc
            if result.returncode:
                raise OTAError(f"host operation failed (exit {result.returncode})")
            if output is not None:
                output.flush()
                os.fsync(output.fileno())
                return b""
            captured.seek(0)
            data = captured.read(MAX_JSON + 1)
            if len(data) > MAX_JSON:
                raise OTAError("host operation returned too much output")
            return data


class Registry:
    """Resolve metadata through Docker's registry client, always pinned after lookup."""
    def __init__(self, config, runner=None):
        self.config, self.runner = config, runner or Runner()

    def inspect(self, ref, field):
        return json.loads(self.runner([
            self.config.docker, "--host", "unix://" + self.config.docker_socket,
            "buildx", "imagetools", "inspect", ref, "--format", "{{json ." + field + "}}"
        ], timeout=90))

    def resolve(self, channel):
        if channel not in CHANNELS:
            raise OTAError("unknown update channel")
        manifest = self.inspect(REPOSITORY + ":" + channel, "Manifest")
        digest = manifest.get("digest", "")
        if not DIGEST.fullmatch(digest):
            raise OTAError("invalid registry manifest digest")
        config_ref = REPOSITORY + "@" + digest
        if "manifests" in manifest:
            targets = [entry for entry in manifest["manifests"]
                       if entry.get("platform", {}).get("os") == "linux"
                       and entry.get("platform", {}).get("architecture") == "amd64"]
            if len(targets) != 1 or not DIGEST.fullmatch(targets[0].get("digest", "")):
                raise OTAError("channel must contain exactly one supported linux/amd64 image")
            config_ref = REPOSITORY + "@" + targets[0]["digest"]
        # Never ask the mutable channel tag for its config in a second request.
        config = self.inspect(config_ref, "Image")
        if (config.get("os"), config.get("architecture")) != ("linux", "amd64"):
            raise OTAError("this OTA release supports linux/amd64 only")
        labels = config.get("config", {}).get("Labels", {}) or {}
        revision = labels.get("org.opencontainers.image.revision", "")
        schema = labels.get("io.artex.ota.schema", "")
        if (labels.get("io.artex.ota.protocol") != "1"
                or labels.get("org.opencontainers.image.source") != SOURCE
                or not REVISION.fullmatch(revision) or not SCHEMA.fullmatch(schema)):
            raise OTAError("image does not declare the trusted ARTEX OTA protocol")
        return {"image": REPOSITORY + "@" + digest, "digest": digest,
                "revision": revision, "schema": schema, "channel": channel}


class Verifier:
    def __init__(self, config, runner=None):
        self.config, self.runner = config, runner or Runner()

    def __call__(self, image):
        if not image.startswith(REPOSITORY + "@") or not DIGEST.fullmatch(image.split("@")[-1]):
            raise OTAError("only pinned ARTEX GHCR images are accepted")
        self.runner([self.config.cosign, "verify", "--certificate-identity", IDENTITY,
                     "--certificate-oidc-issuer", ISSUER, image], timeout=120)


def env_map(inspect):
    return dict(item.split("=", 1) for item in inspect.get("Config", {}).get("Env", []) if "=" in item)


def compose_literal(value):
    # Resolved Compose output contains literal passwords with $. Loading the
    # snapshot must not expand them for a second time.
    if isinstance(value, str):
        return value.replace("$", "$$")
    if isinstance(value, dict):
        return {k: compose_literal(v) for k, v in value.items()}
    if isinstance(value, list):
        return [compose_literal(v) for v in value]
    return value


class DockerBackend:
    def __init__(self, config, runner=None):
        self.config, self.runner = config, runner or Runner()

    def docker(self, *args, **kwargs):
        return self.runner([self.config.docker, "--host", "unix://" + self.config.docker_socket, *args],
                           timeout=kwargs.pop("timeout", self.config.command_timeout), **kwargs)

    def compose(self, *args, snapshot=None, **kwargs):
        c = self.config
        command = ["compose", "--project-directory", str(c.project_dir), "--project-name", c.project_name]
        if snapshot:
            command += ["--env-file", "/dev/null", "-f", str(snapshot)]
        else:
            if c.env_file:
                command += ["--env-file", str(c.env_file)]
            for path in c.compose_files:
                command += ["-f", str(path)]
            if (c.state_dir / "active-image.json").exists():
                command += ["-f", str(c.state_dir / "active-image.json")]
        return self.docker(*command, *args, **kwargs)

    def inspect(self, ref):
        values = json.loads(self.docker("inspect", ref))
        if len(values) != 1:
            raise OTAError("container identity is ambiguous")
        return values[0]

    def service(self, name):
        ids = self.compose("ps", "-a", "-q", name).decode().split()
        if len(ids) != 1 or not re.fullmatch(r"[a-f0-9]{12,64}", ids[0]):
            raise OTAError(f"OTA requires one existing {name} container")
        value = self.inspect(ids[0])
        labels = value.get("Config", {}).get("Labels", {}) or {}
        if (labels.get("com.docker.compose.project") != self.config.project_name
                or labels.get("com.docker.compose.service") != name):
            raise OTAError("container does not belong to the configured deployment")
        return value

    def image_info(self, image):
        values = json.loads(self.docker("image", "inspect", image))
        if len(values) != 1 or not DIGEST.fullmatch(values[0].get("Id", "")):
            raise OTAError("cannot resolve an immutable local image")
        return values[0]

    def current(self):
        app = self.service("artex")
        info = self.image_info(app["Image"])
        return {"image": app["Image"], "revision": (info.get("Config", {}).get("Labels") or {}).get(
            "org.opencontainers.image.revision", ""), "schema": (info.get("Config", {}).get("Labels") or {}).get(
            "io.artex.ota.schema", ""), "container": app["Id"]}

    def ensure_image(self, plan):
        with tempfile.TemporaryFile() as output:
            self.docker("pull", plan["image"], output=output)
        info = self.image_info(plan["image"])
        labels = info.get("Config", {}).get("Labels") or {}
        if (info.get("Architecture") != "amd64" or info.get("Os") != "linux"
                or labels.get("io.artex.ota.protocol") != "1"
                or labels.get("org.opencontainers.image.source") != SOURCE
                or labels.get("org.opencontainers.image.revision") != plan["revision"]
                or labels.get("io.artex.ota.schema") != plan["schema"]):
            raise OTAError("pulled image differs from the reviewed plan")
        return info["Id"]

    def preflight(self):
        c = self.config
        effective = json.loads(self.compose("config", "--format", "json"))
        app, pg = self.service("artex"), self.service("postgres")
        for container in (app, pg):
            if not container.get("State", {}).get("Running"):
                raise OTAError("ARTEX and PostgreSQL must be running before OTA")
        daemon = json.loads(self.docker("info", "--format", "{{json .}}"))
        if daemon.get("OSType") != "linux" or daemon.get("Architecture") not in ("x86_64", "amd64"):
            raise OTAError("this OTA release requires a local linux/amd64 Docker host")
        appenv, pgenv = env_map(app), env_map(pg)
        if app.get("Config", {}).get("WorkingDir") != "/app" or app.get("Config", {}).get("Entrypoint") != ["/app/start.sh"]:
            raise OTAError("OTA requires the standard /app/start.sh entrypoint and /app working directory")
        for mount in app.get("Mounts", []):
            destination = mount.get("Destination", "").rstrip("/") or "/"
            if destination in ("/", "/app", "/app/artex", "/app/start.sh"):
                raise OTAError("a mount hides the application image's executable or entrypoint")
        for identifier in (pgenv.get("POSTGRES_USER", "postgres"),
                           pgenv.get("POSTGRES_DB", pgenv.get("POSTGRES_USER", "postgres"))):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,62}", identifier):
                raise OTAError("OTA requires simple PostgreSQL role/database identifiers; connection strings are not allowed")
        expected = effective.get("services", {}).get("artex", {})
        hashes = self.compose("config", "--hash", "artex").decode().strip().split()
        recorded_hash = (app.get("Config", {}).get("Labels") or {}).get("com.docker.compose.config-hash")
        if len(hashes) != 2 or hashes[0] != "artex" or hashes[1] != recorded_hash:
            raise OTAError("running ARTEX configuration differs from Compose; reconcile configuration first")
        # Changing Compose settings during an OTA must be a separate operation.
        for key, value in (expected.get("environment") or {}).items():
            if value is not None and appenv.get(key) != str(value):
                raise OTAError("running ARTEX environment differs from Compose; reconcile configuration first")
        dsn = urllib.parse.urlsplit(appenv.get("ARTEX_PG_DSN", ""))
        if (dsn.scheme not in ("postgres", "postgresql") or dsn.hostname != "postgres"
                or dsn.port not in (None, 5432)
                or urllib.parse.unquote(dsn.username or "") != pgenv.get("POSTGRES_USER", "postgres")
                or urllib.parse.unquote(dsn.path.removeprefix("/")) != pgenv.get("POSTGRES_DB", pgenv.get("POSTGRES_USER", "postgres"))
                or urllib.parse.parse_qs(dsn.query).keys() - {"sslmode"}):
            raise OTAError("OTA requires ARTEX_PG_DSN to use this deployment's Compose PostgreSQL database")
        data = [m for m in app.get("Mounts", []) if m.get("Destination") == "/app/data"]
        if len(data) != 1 or data[0].get("Type") not in ("bind", "volume"):
            raise OTAError("/app/data must use persistent storage")
        pgmounts = [m for m in pg.get("Mounts", []) if m.get("Destination") == "/var/lib/postgresql/data"]
        if len(pgmounts) != 1 or pgmounts[0].get("Type") != "volume":
            raise OTAError("PostgreSQL must retain its existing named data volume")
        if appenv.get("ARTEX_OTA_STATE_DIR") != "/run/artex-ota-state" or appenv.get("ARTEX_OTA_HEALTH_SOCKET") != HEALTH_SOCKET:
            raise OTAError("bootstrap the OTA mounts and readiness socket before updating")
        public = [m for m in app["Mounts"] if m.get("Destination") == "/run/artex-ota-state"]
        if len(public) != 1 or public[0].get("RW") or Path(public[0].get("Source", "")).resolve() != c.public_dir.resolve():
            raise OTAError("ARTEX must mount this updater's public state directory read-only")
        admission = self.readiness(app["Id"])
        if not all(admission.get(key) is True for key in ("ready", "maintenance", "idle")) or admission.get("ota_protocol") != 1:
            raise OTAError("ARTEX has not confirmed closed admission and idle workloads")
        if admission.get("data_dir") != "/app/data":
            raise OTAError("OTA currently requires the application's actual data directory to be /app/data")
        if shutil.disk_usage(c.state_dir).free < c.min_free_bytes:
            raise OTAError("insufficient free space in the updater backup directory")
        # The running server and mounted cluster must agree. No image pull,
        # recreation or PostgreSQL major upgrade is performed here.
        major = self.docker("exec", pg["Id"], "sh", "-eu", "-c",
                            'test "$(cat "${PGDATA:-/var/lib/postgresql/data}/PG_VERSION")" = "$(postgres --version | sed -E \'s/.* ([0-9]+).*/\\1/\')"').decode()
        del major
        record = {"config": effective, "app": app, "postgres": pg, "daemon": daemon.get("ID"),
                  "config_hash": hashlib.sha256(canonical(effective)).hexdigest(),
                  "db_user": pgenv.get("POSTGRES_USER", "postgres"),
                  "db_name": pgenv.get("POSTGRES_DB", pgenv.get("POSTGRES_USER", "postgres")),
                  "old_image": app["Image"], "old_schema": (self.image_info(app["Image"]).get("Config", {}).get("Labels") or {}).get("io.artex.ota.schema", "")}
        record["gate_enabled"] = admission.get("gate_enabled", True)
        record["has_default_config"] = self.docker(
            "exec", app["Id"], "python3", "-c",
            'from pathlib import Path; print(int(Path("/app/config.json").exists()))').strip() == b"1"
        return record

    def assert_unchanged(self, record):
        current = self.preflight()
        for key in ("config_hash", "daemon", "old_image"):
            if current[key] != record[key]:
                raise OTAError("deployment changed after preflight")
        for key in ("app", "postgres"):
            if current[key]["Id"] != record[key]["Id"]:
                raise OTAError("container changed after preflight")

    def stop(self, record):
        self.docker("stop", "--time", "45", record["app"]["Id"], timeout=60)
        if self.inspect(record["app"]["Id"])["State"]["Running"]:
            raise OTAError("ARTEX did not stop")

    def backup(self, record, directory):
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        atomic_json(directory / "deployment.json", record)
        pg = record["postgres"]["Id"]
        with (directory / "postgres.dump").open("xb") as out:
            os.fchmod(out.fileno(), 0o600)
            self.docker("exec", pg, "pg_dump", "--format=custom", "--no-owner", "--username", record["db_user"],
                        "--dbname", record["db_name"], output=out)
        # Parse the archive using the SAME server's tools, without restoring it.
        with (directory / "postgres.dump").open("rb") as source:
            self.docker("exec", "-i", pg, "pg_restore", "--list", input_file=source)
        with (directory / "data.tar").open("xb") as out:
            os.fchmod(out.fileno(), 0o600)
            self.docker("cp", record["app"]["Id"] + ":/app/data/.", "-", output=out)
        with tarfile.open(directory / "data.tar", mode="r|*") as archive:
            if archive.next() is None:
                raise OTAError("application data backup is empty")
        retained = self.retain_runtime(record["app"], directory, record.get("has_default_config", False), record.get("gate_enabled"))
        hashes = {}
        for path in directory.iterdir():
            if path.is_file():
                with path.open("rb") as stream:
                    hashes[path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
        atomic_json(directory / "manifest.json", {"created_at": timestamp(), "sha256": hashes})
        return retained

    def retain_runtime(self, app, directory, has_default_config=False, gate_enabled=None):
        # Keep encryption/signing keys outside the user-browsable workspace.
        # Bind each saved regular file into replacements; never generate a key.
        keydir = env_map(app).get("ARTEX_KEY_DIR", "").strip() or "/app"
        if not keydir.startswith("/") or ":" in keydir or ".." in Path(keydir).parts:
            raise OTAError("unsupported ARTEX_KEY_DIR")
        paths = [keydir.rstrip("/") + "/jwt.key"]
        gate = env_map(app).get("ARTEX_GATE", "").strip().lower()
        if gate_enabled is True or (gate_enabled is None and gate not in ("off", "false", "0")):
            paths.append("/app/gate.key")
        # ARTEX_CONFIG can carry settings beyond the database DSN.
        config_path = env_map(app).get("ARTEX_CONFIG", "").strip()
        if not config_path and has_default_config:
            config_path = "/app/config.json"
        if config_path:
            if not config_path.startswith("/") or ":" in config_path or ".." in Path(config_path).parts:
                raise OTAError("ARTEX_CONFIG must be an absolute path for OTA")
            paths.append(config_path)
        retained = []
        for index, path in enumerate(paths):
            dest = directory / f"retained-{index}"
            self.docker("cp", app["Id"] + ":" + path, str(dest))
            if not stat.S_ISREG(dest.lstat().st_mode) or dest.stat().st_size > MAX_JSON:
                raise OTAError("retained key/config is not a bounded regular file")
            if path.endswith(".key") and len(dest.read_bytes().strip()) < 32:
                raise OTAError("retained authentication key is invalid; refusing replacement")
            os.chmod(dest, 0o600)
            private = self.config.state_dir / "retained"
            private.mkdir(mode=0o700, exist_ok=True)
            permanent = private / hashlib.sha256(dest.read_bytes()).hexdigest()
            if permanent.exists():
                if not stat.S_ISREG(permanent.lstat().st_mode) or permanent.read_bytes() != dest.read_bytes():
                    raise OTAError("persisted runtime file changed")
            else:
                with permanent.open("xb") as out:
                    os.fchmod(out.fileno(), 0o600)
                    out.write(dest.read_bytes())
                    out.flush()
                    os.fsync(out.fileno())
            covering = [mount for mount in app.get("Mounts", [])
                        if mount.get("Type") in ("bind", "volume")
                        and (path == mount.get("Destination") or path.startswith(mount.get("Destination", "").rstrip("/") + "/"))]
            if covering:
                existing = max(covering, key=lambda mount: len(mount["Destination"]))
                source = Path(existing.get("Source", "/"))
                if source.parent.resolve() != private.resolve():
                    # The operator already persists this file. Its original
                    # mount stays in the base Compose configuration; do not
                    # replace that source or break their configuration rotation.
                    continue
            retained.append({"type": "bind", "source": str(permanent), "target": path, "read_only": True,
                             "bind": {"create_host_path": False}})
        return retained

    def snapshot(self, record, image, retained, path):
        effective = copy.deepcopy(record["config"])
        app = effective["services"]["artex"]
        app.pop("build", None)
        app["image"] = image
        app["pull_policy"] = "never"
        volumes = app.setdefault("volumes", [])
        targets = {x["target"] for x in retained}
        app["volumes"] = [x for x in volumes if x.get("target") not in targets] + retained
        atomic_json(path, compose_literal(effective))
        return path

    def start(self, snapshot, expected_image):
        self.compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", "artex", snapshot=snapshot)
        ids = self.compose("ps", "-a", "-q", "artex", snapshot=snapshot).decode().split()
        if len(ids) != 1:
            raise OTAError("replacement container identity is ambiguous")
        current = self.inspect(ids[0])
        if current.get("Image") != expected_image:
            raise OTAError("replacement does not use the verified image")
        return current["Id"]

    def health(self, container, expected_image, pg_id):
        deadline = time.monotonic() + self.config.health_timeout
        consecutive = 0
        while time.monotonic() < deadline:
            try:
                current = self.inspect(container)
                if current.get("Image") != expected_image:
                    raise OTAError("replacement image changed")
                if self.service("postgres")["Id"] != pg_id:
                    raise OTAError("PostgreSQL container changed during update")
                data = self.readiness(container)
                if (all(data.get(key) is True for key in ("ready", "maintenance", "idle"))
                        and data.get("ota_protocol") == 1 and data.get("data_dir") == "/app/data"):
                    consecutive += 1
                    if consecutive >= 3:
                        return
                else:
                    consecutive = 0
            except (OTAError, ValueError, KeyError):
                consecutive = 0
            time.sleep(2)
        raise OTAError("replacement did not pass database and application readiness")

    def readiness(self, container):
        return json.loads(self.docker("exec", container, "curl", "--fail", "--silent", "--max-time", "5",
                                      "--unix-socket", HEALTH_SOCKET, "http://localhost/health", timeout=10))

    def persist(self, image, retained):
        # The host CLI includes this last, making subsequent managed Compose
        # operations reproduce the chosen digest and preserved keys.
        atomic_json(self.config.state_dir / "active-image.json", compose_literal({
            "services": {"artex": {"image": image, "pull_policy": "never", "volumes": retained}}}))

    def stop_failed(self, image):
        app = self.service("artex")
        if app.get("Image") == image:
            self.docker("stop", "--time", "30", app["Id"], timeout=45)


class Updater:
    def __init__(self, config, backend=None, registry=None, verifier=None):
        self.config = config
        self.backend = backend or DockerBackend(config)
        self.registry = registry or Registry(config)
        self.verifier = verifier or Verifier(config)
        self.lock = threading.RLock()
        self.plans = {}
        config.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if config.state_dir.is_symlink():
            raise OTAError("state directory cannot be a symlink")
        os.chmod(config.state_dir, 0o700)
        config.public_dir.mkdir(mode=0o755, exist_ok=True)
        os.chmod(config.public_dir, 0o755)
        self.path = config.state_dir / "state.json"
        self.state = read_json(self.path) if self.path.exists() else {"state": "idle", "active": False, "history": []}
        if self.state.get("active") or config.marker.exists():
            self.state.update(state="recovery_required", active=False,
                              message="Updater interrupted; inspect backups and the running container before recovery")
            atomic_json(config.marker, {"reason": "interrupted", "time": timestamp()}, 0o644)
            self.save()
        elif not self.path.exists():
            self.save()

    def save(self):
        self.state["updated_at"] = timestamp()
        atomic_json(self.path, self.state)

    def transition(self, phase, message):
        with self.lock:
            self.state.update(state=phase, message=message)
            self.save()

    def progress(self, **fields):
        with self.lock:
            self.state.update(fields)
            self.save()

    def status(self):
        with self.lock:
            return {"enabled": True, **{k: v for k, v in self.state.items() if k != "previous"},
                    "rollback_available": bool(self.state.get("previous", {}).get("schema"))
                    and self.state.get("previous", {}).get("schema") == self.state.get("current_schema")
                    and not self.state.get("active") and self.state.get("state") != "recovery_required"}

    def check(self, channel):
        if channel not in CHANNELS:
            raise OTAError("unknown update channel")
        with self.lock:
            if self.state.get("active") or self.state.get("state") == "recovery_required":
                raise OTAError("another update or recovery is pending")
            # Serialized with submit so the current-image comparison is stable.
            plan = self.registry.resolve(channel)
            self.verifier(plan["image"])
            current = self.backend.current()
            plan.update(plan_id=uuid.uuid4().hex, expires_at=time.time() + 900,
                        current_image=current["image"], current_revision=current["revision"],
                        rollback_safe=bool(current["schema"]) and current["schema"] == plan["schema"])
            self.plans = {plan["plan_id"]: plan}
            return plan.copy()

    def submit(self, plan_id=None, operation="apply"):
        with self.lock:
            if self.state.get("active") or self.state.get("state") == "recovery_required":
                raise OTAError("another update or recovery is pending")
            if operation == "rollback":
                if not self.status()["rollback_available"]:
                    raise OTAError("previous image is not compatible with the current migration fingerprint")
                previous = self.state["previous"]
                plan = {"image": previous["image"], "digest": previous["image"], "schema": previous["schema"],
                        "revision": previous.get("revision", ""), "current_image": self.state["current_image"],
                        "local_previous": True}
            else:
                plan = self.plans.pop(plan_id, None)
                if plan is None or plan["expires_at"] < time.time():
                    raise OTAError("update plan expired; check the channel again")
            job = uuid.uuid4().hex
            # The caller holds its admission barrier until this durable marker
            # and journal are acknowledged. Never launch the worker beforehand.
            atomic_json(self.config.marker, {"job_id": job, "time": timestamp()}, 0o644)
            self.state.update(state="queued", active=True, job_id=job, operation=operation,
                              message="Update accepted; workload admission is closed", source_image=plan["current_image"],
                              target_digest=plan.get("digest"), target_revision=plan.get("revision"),
                              channel=plan.get("channel", "rollback"), target_image=None, backup=None)
            self.save()
            worker = threading.Thread(target=self.run_job, args=(plan, operation), daemon=False)
            worker.start()
            return self.status()

    def finish(self, phase, message, release):
        with self.lock:
            self.state.update(state=phase, active=False, message=message)
            history = self.state.setdefault("history", [])
            history.append({"job_id": self.state.get("job_id"), "operation": self.state.get("operation"),
                            "state": phase, "message": message, "time": timestamp(),
                            **{key: self.state.get(key) for key in ("source_image", "target_image", "target_digest",
                                                                   "target_revision", "current_image", "channel")}})
            self.state["history"] = history[-20:]
            # Journal first, marker last: interruption at either point keeps
            # admission closed and requires explicit host recovery.
            self.save()
            if release:
                self.config.marker.unlink(missing_ok=True)
                fd = os.open(self.config.public_dir, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)

    def run_job(self, plan, operation="apply"):
        record = None
        stopped = False
        attempted_start = False
        retained = []
        backup_dir = self.config.state_dir / "backups" / self.state["job_id"]
        try:
            self.transition("verifying", "Verifying the reviewed image and downloading immutable layers")
            if plan.get("local_previous"):
                image = self.backend.image_info(plan["image"])["Id"]
            else:
                self.verifier(plan["image"])
                image = self.backend.ensure_image(plan)
            self.progress(target_image=image)
            self.transition("preflight", "Checking deployment identity, storage and PostgreSQL compatibility")
            record = self.backend.preflight()
            self.progress(current_image=record["old_image"], current_schema=record["old_schema"])
            if record["old_image"] != plan["current_image"]:
                raise OTAError("running image changed since the update was reviewed")
            self.backend.assert_unchanged(record)
            self.transition("stopping", "Stopping ARTEX after workload admission was closed")
            # Treat a timed-out stop as possibly stopped; recovery must inspect.
            stopped = True
            self.backend.stop(record)
            self.transition("backup", "Backing up PostgreSQL, application data, configuration and encryption keys")
            self.progress(backup=str(backup_dir))
            retained = self.backend.backup(record, backup_dir)
            old_snapshot = self.backend.snapshot(record, record["old_image"], retained, backup_dir / "previous-compose.json")
            new_snapshot = self.backend.snapshot(record, image, retained, backup_dir / "candidate-compose.json")
            self.transition("starting", "Starting the verified ARTEX image; PostgreSQL is retained")
            # Startup can apply migrations even when Compose reports failure.
            attempted_start = True
            container = self.backend.start(new_snapshot, image)
            self.transition("healthcheck", "Checking the exact replacement container and database readiness")
            self.backend.health(container, image, record["postgres"]["Id"])
            self.backend.persist(image, retained)
            old_info = self.backend.image_info(record["old_image"])
            self.progress(current_image=image, current_schema=plan["schema"],
                          current_revision=plan.get("revision", ""), previous_image=record["old_image"],
                          previous={"image": record["old_image"], "schema": record["old_schema"],
                                    "revision": (old_info.get("Config", {}).get("Labels") or {}).get("org.opencontainers.image.revision", "")})
            self.finish("completed" if operation == "apply" else "rolled_back", "Verified deployment is ready", True)
        except Exception as exc:
            message = str(exc) if isinstance(exc, OTAError) else "Updater operation failed; inspect host prerequisites and backups"
            if not stopped:
                self.finish("failed", message + "; running deployment retained", True)
                return
            compatible = bool(record and record["old_schema"]) and record["old_schema"] == plan.get("schema")
            if attempted_start and not compatible:
                try:
                    self.backend.stop_failed(image)
                except Exception:
                    pass  # The durable maintenance marker still prevents admission.
                self.finish("recovery_required", message + "; migration fingerprint changed, so automatic rollback is disabled", False)
                return
            try:
                self.transition("starting", "Recovering the previous immutable image")
                if not attempted_start:
                    # No candidate ever ran: restarting the exact old container
                    # also retains keys even when backup itself failed.
                    self.backend.docker("start", record["app"]["Id"])
                    container = record["app"]["Id"]
                else:
                    container = self.backend.start(old_snapshot, record["old_image"])
                self.backend.health(container, record["old_image"], record["postgres"]["Id"])
                if attempted_start:
                    self.backend.persist(record["old_image"], retained)
                self.finish("rolled_back", message + "; previous image passed readiness", True)
            except Exception:
                self.finish("recovery_required", message + "; previous deployment needs host recovery", False)


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        return connection, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ARTEX-Updater"

    def log_message(self, fmt, *args):
        pass  # Request URLs/headers are intentionally not written to logs.

    def reply(self, status, data):
        body = canonical(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/status":
            self.reply(200, self.server.updater.status())
        else:
            self.reply(404, {"error": "unknown updater operation"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 1024 or self.headers.get("Transfer-Encoding"):
                raise OTAError("invalid request size")
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise OTAError("request must be an object")
            if self.path == "/v1/check" and set(value) == {"channel"}:
                self.reply(200, self.server.updater.check(value["channel"]))
            elif self.path == "/v1/apply" and set(value) == {"plan_id"} and isinstance(value["plan_id"], str):
                self.reply(202, self.server.updater.submit(value["plan_id"]))
            elif self.path == "/v1/rollback" and not value:
                self.reply(202, self.server.updater.submit(operation="rollback"))
            else:
                self.reply(400, {"error": "unknown operation or unexpected fields"})
        except (OTAError, ValueError, TypeError) as exc:
            self.reply(409 if isinstance(exc, OTAError) else 400,
                       {"error": str(exc) if isinstance(exc, OTAError) else "invalid request"})
        except Exception:
            self.reply(500, {"error": "updater operation failed"})


def deployment_locks(config):
    config.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(config.state_dir / "daemon.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise OTAError("another updater is using this state directory") from exc
    daemon = json.loads(DockerBackend(config).docker("info", "--format", "{{json .ID}}"))
    lock_name = hashlib.sha256((daemon + ":" + config.project_name).encode()).hexdigest()
    deployment_fd = os.open("/run/lock/artex-ota-" + lock_name + ".lock",
                            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(deployment_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(deployment_fd)
        raise OTAError("another updater manages this Docker deployment") from exc
    return fd, deployment_fd


def serve(config):
    locks = deployment_locks(config)
    updater = Updater(config)
    config.socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if config.socket_path.exists():
        if not stat.S_ISSOCK(config.socket_path.lstat().st_mode):
            raise OTAError("refusing to replace a non-socket API path")
        config.socket_path.unlink()
    with UnixHTTPServer(str(config.socket_path), Handler) as server:
        os.chmod(config.socket_path, 0o660)
        server.updater = updater
        server.serve_forever()


def prepare(config):
    """Read-only Docker bootstrap: preserve keys before the first recreation."""
    locks = deployment_locks(config)
    del locks  # Descriptors remain open until this short-lived CLI exits.
    updater = Updater(config)
    if updater.state.get("state") != "idle" or (config.state_dir / "active-image.json").exists():
        raise OTAError("deployment is already managed; prepare cannot replace existing state")
    backend = updater.backend
    app = backend.service("artex")
    if not app.get("State", {}).get("Running"):
        raise OTAError("start the existing application before preserving its runtime keys")
    default_config = backend.docker("exec", app["Id"], "python3", "-c",
                                   'from pathlib import Path; print(int(Path("/app/config.json").exists()))').strip() == b"1"
    initial = config.state_dir / ("bootstrap-" + uuid.uuid4().hex)
    initial.mkdir(mode=0o700)
    retained = backend.retain_runtime(app, initial, default_config)
    atomic_json(config.state_dir / "active-image.json", compose_literal({
        "services": {"artex": {"volumes": retained}}}))
    print("Runtime keys/configuration preserved. Build the OTA-capable application and recreate only artex through the managed compose command.")


def recover(config, expected_image):
    """Explicit LOCAL reconciliation after an operator has restored the service.

    This never starts a container, replays a dump, or reverses a migration. The
    caller must select a recorded image and pass full readiness before admission
    is released. The daemon must be stopped so recovery cannot race a job.
    """
    locks = deployment_locks(config)
    del locks
    updater = Updater(config)
    if updater.state.get("state") != "recovery_required":
        raise OTAError("no interrupted update is awaiting recovery")
    if not DIGEST.fullmatch(expected_image) or expected_image not in {
            updater.state.get("source_image"), updater.state.get("target_image"), updater.state.get("current_image")}:
        raise OTAError("recovery requires an exact image ID recorded for the interrupted operation")
    backend = updater.backend
    app = backend.service("artex")
    if app.get("Image") != expected_image or not app.get("State", {}).get("Running"):
        raise OTAError("restore and start the selected image before acknowledging recovery")
    path = config.state_dir / "active-image.json"
    previous = read_json(path) if path.exists() else {"services": {"artex": {}}}
    override = copy.deepcopy(previous)
    override["services"]["artex"]["image"] = expected_image
    override["services"]["artex"]["pull_policy"] = "never"
    # A manual restoration from previous-compose.json already carries retained
    # keys. Reconstruct ONLY those known updater-owned runtime file mounts.
    retained_root = (config.state_dir / "retained").resolve()
    mounts = []
    for mount in app.get("Mounts", []):
        source = Path(mount.get("Source", "/"))
        if mount.get("Type") == "bind" and source.parent.resolve() == retained_root and not mount.get("RW"):
            mounts.append({"type": "bind", "source": str(source), "target": mount["Destination"],
                           "read_only": True, "bind": {"create_host_path": False}})
    override["services"]["artex"]["volumes"] = compose_literal(mounts)
    atomic_json(path, override)
    try:
        record = backend.preflight()
        backend.health(app["Id"], expected_image, record["postgres"]["Id"])
    except Exception:
        atomic_json(path, previous)
        raise
    info = backend.image_info(expected_image)
    labels = info.get("Config", {}).get("Labels") or {}
    updater.state.update(current_image=expected_image, current_schema=labels.get("io.artex.ota.schema", ""),
                         current_revision=labels.get("org.opencontainers.image.revision", ""), previous={})
    updater.finish("completed", "Host operator acknowledged restored deployment after readiness verification", True)
    print("Restored deployment verified; workload admission reopened. Restart artex-updater.service.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/artex-updater/config.json")
    parser.add_argument("command", choices=("serve", "status", "compose", "prepare", "recover"))
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        config = Config.load(args.config)
        if args.command == "serve":
            serve(config)
        elif args.command == "prepare":
            prepare(config)
        elif args.command == "recover":
            if len(args.args) != 2 or args.args[0] != "--image":
                raise OTAError("usage: recover --image sha256:<recorded-local-image-id>")
            recover(config, args.args[1])
        elif args.command == "status":
            state = read_json(config.state_dir / "state.json")
            print(json.dumps({k: v for k, v in state.items() if k != "previous"}, indent=2))
        else:
            # A local operator already has host access; these are CLI arguments,
            # never accepted through the HTTP API. Keep managed digest overlays.
            def operator_command(argv, **_kwargs):
                result = subprocess.run(argv, check=False)
                if result.returncode:
                    raise OTAError(f"Compose exited with status {result.returncode}")
                return b""
            DockerBackend(config, operator_command).compose(*args.args)
    except (OTAError, OSError, ValueError) as exc:
        print(f"artex-updater: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
