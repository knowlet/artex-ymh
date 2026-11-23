#!/usr/bin/env python3
"""Run the real preflight shell against disposable directories without Docker."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PostgresVersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = self.root / "data with spaces"
        self.data.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls.jsonl"
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}",
            PGDATA=str(self.data),
            TEST_POSTGRES_VERSION="postgres (PostgreSQL) 16.12",
            TEST_CALLS=str(self.calls),
        )
        # Execute precisely the shell body sent to Docker. Any extra invocation
        # (entrypoint/initdb/server startup included) fails instead of being faked.
        self.executable(
            "docker",
            f"#!{sys.executable}\n"
            "import json, os, subprocess, sys\n"
            "args = sys.argv[1:]\n"
            "prefix = ['compose', 'run', '--rm', '--no-deps', '-T', '--entrypoint', 'sh', 'postgres', '-ec']\n"
            "with open(os.environ['TEST_CALLS'], 'a') as log:\n"
            "    logged = args[:-1] if args[:-1] == prefix else args\n"
            "    log.write(json.dumps(logged) + '\\n')\n"
            "if args[:3] == ['compose', 'config', '--format']:\n"
            "    mode = os.environ.get('TEST_VOLUME_CONFIG', 'named')\n"
            "    if mode == 'anon':\n"
            "        doc = {'services': {'postgres': {'volumes': [{'type': 'volume', 'target': '/var/lib/postgresql/data', 'volume': {}}]}}}\n"
            "    elif mode == 'bind':\n"
            "        doc = {'services': {'postgres': {'volumes': [{'type': 'bind', 'source': '/tmp/pg', 'target': '/var/lib/postgresql/data'}]}}}\n"
            "    elif mode == 'missing':\n"
            "        doc = {'services': {'postgres': {}}}\n"
            "    else:\n"
            "        doc = {'services': {'postgres': {'volumes': [{'type': 'volume', 'source': 'pgdata', 'target': '/var/lib/postgresql/data', 'volume': {}}]}}, 'volumes': {'pgdata': {'name': 'test_pgdata'}}}\n"
            "    sys.stdout.write(json.dumps(doc))\n"
            "    sys.exit(0)\n"
            "if args[:-1] != prefix:\n"
            "    sys.exit('unexpected Docker invocation')\n"
            "sys.exit(subprocess.run(['/bin/sh', '-ec', args[-1]]).returncode)\n",
        )
        self.executable(
            "postgres",
            '#!/bin/sh\n'
            'test "$#" = 1 && test "$1" = --version || exit 99\n'
            'printf "%s\\n" "$TEST_POSTGRES_VERSION"\n',
        )

    def executable(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def cluster(self, major):
        (self.data / "PG_VERSION").write_text(major + "\n")
        (self.data / "sentinel").write_bytes(b"existing database contents\x00\xff")

    def run_guard(self):
        before = {p.name: p.read_bytes() for p in self.data.iterdir() if p.is_file()}
        pgdata = self.env.get("PGDATA", "")
        host = str(self.data)
        env = self.env.copy()
        if pgdata == host or pgdata.startswith(host + "/"):
            # The preflight requires the named volume to be mounted. Bind the
            # disposable directory there and address it by that path.
            env["PGDATA"] = "/var/lib/postgresql/data" + pgdata[len(host):]
            env["HOST_VOLUME"] = host
            env["PREFLIGHT_SCRIPT"] = str(ROOT / "scripts/check_postgres_version.sh")
            result = subprocess.run(
                [
                    "unshare", "--user", "--mount", "--map-root-user",
                    "bash", "-c",
                    """
set -euo pipefail
mount -t tmpfs tmpfs /var/lib
mkdir -p /var/lib/postgresql/data
mount --bind "$HOST_VOLUME" /var/lib/postgresql/data
exec bash "$PREFLIGHT_SCRIPT"
""",
                ],
                cwd=self.root,
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
            )
        else:
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/check_postgres_version.sh")],
                cwd=self.root,
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
            )
        after = {p.name: p.read_bytes() for p in self.data.iterdir() if p.is_file()}
        self.assertEqual(before, after, "preflight changed the data directory")
        self.assert_volume_then_one_run()
        return result

    def test_pg16_volume_rejects_pg17_without_changing_data(self):
        self.cluster("16")
        self.env["TEST_POSTGRES_VERSION"] = "postgres (PostgreSQL) 17.12"
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Data directory uses PostgreSQL 16", result.stderr)
        self.assertIn("image runs PostgreSQL 17", result.stderr)
        self.assertIn("docs/POSTGRES-UPGRADE.md", result.stderr)

    def test_pg17_volume_rejects_pg16_without_changing_data(self):
        self.cluster("17")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Data directory uses PostgreSQL 17", result.stderr)

    def test_same_major_accepts_minor_update(self):
        self.cluster("16")
        self.env["TEST_POSTGRES_VERSION"] = "postgres (PostgreSQL) 16.99"
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("existing PG16 cluster matches server 16.99", result.stdout)

    def test_existing_pg17_remains_supported(self):
        self.cluster("17")
        self.env["TEST_POSTGRES_VERSION"] = "postgres (PostgreSQL) 17.12"
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_debian_image_version_suffix(self):
        self.cluster("16")
        self.env["TEST_POSTGRES_VERSION"] = "postgres (PostgreSQL) 16.12 (Debian 16.12-1.pgdg12+1)"
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_data_is_not_initialized_by_preflight(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("empty PGDATA", result.stdout)
        self.assertEqual(list(self.data.iterdir()), [])

    def test_missing_pgdata_subdirectory_is_not_created(self):
        self.env["PGDATA"] = str(self.data / "cluster")
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.data / "cluster").exists())

    def test_nonempty_directory_without_version_is_rejected(self):
        (self.data / "sentinel").write_text("preserve this")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Nonempty PGDATA has no PG_VERSION", result.stderr)

    def test_invalid_cluster_version_is_rejected(self):
        self.cluster("corrupt")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid PG_VERSION", result.stderr)

    def test_empty_version_file_is_rejected(self):
        self.cluster("")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid PG_VERSION", result.stderr)

    def test_version_directory_is_rejected(self):
        (self.data / "PG_VERSION").mkdir()
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PG_VERSION is not a regular file", result.stderr)

    def test_relative_pgdata_is_rejected(self):
        self.env["PGDATA"] = "relative/cluster"
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PGDATA must be an absolute path", result.stderr)

    def test_unknown_server_version_fails_closed(self):
        self.env["TEST_POSTGRES_VERSION"] = "unrecognized server"
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unrecognized postgres --version", result.stderr)

    def test_missing_named_volume_stops_before_the_container(self):
        self.env["TEST_VOLUME_CONFIG"] = "missing"
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not mount a named volume", result.stderr)
        self.assertIn("anonymous volume from the image", result.stderr)

    def test_explicit_anonymous_volume_stops_before_the_container(self):
        self.env["TEST_VOLUME_CONFIG"] = "anon"
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not mount a named volume", result.stderr)

    def test_bind_mount_is_not_the_named_volume(self):
        self.env["TEST_VOLUME_CONFIG"] = "bind"
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not mount a named volume", result.stderr)

    def test_compose_pins_pgdata_on_named_volume(self):
        text = (ROOT / "docker-compose.yml").read_text()
        self.assertIn("pgdata:/var/lib/postgresql/data", text)
        self.assertRegex(text, r"(?m)^\s+PGDATA:\s*/var/lib/postgresql/data\s*$")

    def test_healthchecks_wait_for_tcp_not_the_init_socket(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertRegex(
            compose,
            r'(?m)^\s+test:\s*\["CMD-SHELL", "pg_isready -h 127\.0\.0\.1 -U \$\{POSTGRES_USER:-artex\} -d \$\{POSTGRES_DB:-artex\}"\]\s*$',
        )
        document = (ROOT / "docs/POSTGRES-UPGRADE.md").read_text()
        self.assertIn(
            'test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]',
            document,
        )

    def run_with_mounted_volume(self, pgdata, populate, setup=""):
        volume = self.root / "mounted-volume"
        volume.mkdir()
        populate(volume)
        before = {p.name: p.read_bytes() for p in volume.iterdir() if p.is_file()}
        env = self.env.copy()
        env.update(
            PGDATA=pgdata,
            HOST_VOLUME=str(volume),
            PREFLIGHT_SCRIPT=str(ROOT / "scripts/check_postgres_version.sh"),
            PREFLIGHT_SETUP=setup,
        )
        result = subprocess.run(
            [
                "unshare", "--user", "--mount", "--map-root-user",
                "bash", "-c",
                """
set -euo pipefail
mount -t tmpfs tmpfs /var/lib
mkdir -p /var/lib/postgresql/data
mount --bind "$HOST_VOLUME" /var/lib/postgresql/data
if [ -n "${PREFLIGHT_SETUP:-}" ]; then
  eval "$PREFLIGHT_SETUP"
fi
set +e
bash "$PREFLIGHT_SCRIPT"
status=$?
set -e
if [ -e /var/lib/postgresql/18 ]; then
  printf '%s\\n' 'preflight created the image-default data directory' >&2
  exit 99
fi
exit "$status"
""",
            ],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
        )
        after = {p.name: p.read_bytes() for p in volume.iterdir() if p.is_file()}
        self.assertEqual(before, after, "preflight changed the mounted volume")
        self.assertTrue(
            self.calls.exists(),
            "preflight never reached Docker inside the mount namespace "
            f"(exit {result.returncode}): {result.stderr}",
        )
        self.assert_volume_then_one_run()
        return result

    def assert_volume_then_one_run(self):
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        configs = [call for call in calls if call[:2] == ["compose", "config"]]
        runs = [call for call in calls if call[:2] == ["compose", "run"]]
        self.assertEqual(len(configs), 1, calls)
        mode = self.env.get("TEST_VOLUME_CONFIG", "named")
        if mode == "named":
            self.assertEqual(len(runs), 1, "preflight invoked an extra container operation")
        else:
            self.assertEqual(runs, [], "preflight started a container without a named volume")
        return calls

    def test_image_default_pgdata_outside_mounted_volume_is_rejected(self):
        result = self.run_with_mounted_volume("/var/lib/postgresql/18/docker", lambda volume: None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the mounted volume /var/lib/postgresql/data", result.stderr)
        self.assertIn("/var/lib/postgresql/18/docker", result.stderr)
        self.assertNotIn("empty PGDATA", result.stdout)

    def test_empty_mounted_volume_root_can_initialize(self):
        result = self.run_with_mounted_volume("/var/lib/postgresql/data", lambda volume: None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("empty PGDATA", result.stdout)

    def test_nonempty_legacy_directory_without_version_is_rejected(self):
        def populate(volume):
            (volume / "partial.dat").write_text("incomplete cluster")

        result = self.run_with_mounted_volume("/var/lib/postgresql/data/pgdata", populate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Nonempty data directory at /var/lib/postgresql/data has no PG_VERSION", result.stderr)
        self.assertIn("PGDATA is /var/lib/postgresql/data/pgdata", result.stderr)
        self.assertNotIn("empty PGDATA", result.stdout)

    def test_changed_pgdata_still_rejects_legacy_cluster(self):
        def populate(volume):
            (volume / "PG_VERSION").write_text("16\n")
            (volume / "sentinel").write_bytes(b"existing")

        result = self.run_with_mounted_volume("/var/lib/postgresql/data/pgdata", populate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Existing cluster found at /var/lib/postgresql/data", result.stderr)
        self.assertIn("PGDATA is /var/lib/postgresql/data/pgdata", result.stderr)

    def test_dotdot_pgdata_outside_mount_is_rejected(self):
        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/../other", lambda volume: None
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the mounted volume /var/lib/postgresql/data", result.stderr)
        self.assertIn("/var/lib/postgresql/data/../other", result.stderr)
        self.assertNotIn("empty PGDATA", result.stdout)

    def test_dotdot_back_onto_the_volume_can_initialize(self):
        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/../data", lambda volume: None
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("empty PGDATA", result.stdout)

    def test_symlink_pgdata_outside_mount_is_rejected(self):
        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/escape",
            lambda volume: None,
            "mkdir -p /var/lib/postgresql/outside\n"
            "ln -s /var/lib/postgresql/outside /var/lib/postgresql/data/escape\n",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the mounted volume /var/lib/postgresql/data", result.stderr)
        self.assertIn("/var/lib/postgresql/data/escape", result.stderr)
        self.assertNotIn("empty PGDATA", result.stdout)

    def test_dotdot_alias_of_existing_cluster_matches(self):
        def populate(volume):
            (volume / "PG_VERSION").write_text("16\n")
            (volume / "sentinel").write_bytes(b"existing")

        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/../data", populate
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("existing PG16 cluster matches server 16.12", result.stdout)

    def test_dotdot_alias_still_rejects_major_mismatch(self):
        self.env["TEST_POSTGRES_VERSION"] = "postgres (PostgreSQL) 17.12"

        def populate(volume):
            (volume / "PG_VERSION").write_text("16\n")

        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/../data", populate
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Data directory uses PostgreSQL 16", result.stderr)
        self.assertNotIn("Existing cluster found", result.stderr)

    def test_symlink_to_the_mounted_cluster_matches(self):
        def populate(volume):
            (volume / "PG_VERSION").write_text("16\n")

        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/alias",
            populate,
            "ln -s /var/lib/postgresql/data /var/lib/postgresql/data/alias\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("existing PG16 cluster matches server 16.12", result.stdout)

    def test_missing_subdirectory_on_empty_volume_can_initialize(self):
        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/pgdata", lambda volume: None
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("empty PGDATA", result.stdout)

    def test_cluster_in_configured_subdirectory_is_accepted(self):
        def populate(volume):
            cluster = volume / "pgdata"
            cluster.mkdir()
            (cluster / "PG_VERSION").write_text("16\n")
            (cluster / "sentinel").write_bytes(b"existing")

        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/pgdata", populate
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("existing PG16 cluster matches server 16.12", result.stdout)

    def test_sibling_beside_configured_subdirectory_is_rejected(self):
        def populate(volume):
            cluster = volume / "pgdata"
            cluster.mkdir()
            (cluster / "PG_VERSION").write_text("16\n")
            (volume / "partial.dat").write_text("unrelated")

        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/pgdata", populate
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Nonempty data directory at /var/lib/postgresql/data has no PG_VERSION",
            result.stderr,
        )
        self.assertIn("PGDATA is /var/lib/postgresql/data/pgdata", result.stderr)

    def test_missing_volume_mount_rejects_empty_pgdata(self):
        env = self.env.copy()
        env.update(
            PGDATA="/var/lib/postgresql/18/docker",
            PREFLIGHT_SCRIPT=str(ROOT / "scripts/check_postgres_version.sh"),
        )
        result = subprocess.run(
            [
                "unshare", "--user", "--mount", "--map-root-user",
                "bash", "-c",
                """
set -euo pipefail
mount -t tmpfs tmpfs /var/lib
mkdir -p /var/lib/postgresql/data
exec bash "$PREFLIGHT_SCRIPT"
""",
            ],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("not mounted at /var/lib/postgresql/data", result.stderr)
        self.assertNotIn("empty PGDATA", result.stdout)

    def test_dotdot_through_missing_component_sees_existing_cluster(self):
        def populate(volume):
            (volume / "PG_VERSION").write_text("16\n")
            (volume / "sentinel").write_bytes(b"existing")

        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/missing/..", populate
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("existing PG16 cluster matches server 16.12", result.stdout)
        self.assertNotIn("empty PGDATA", result.stdout)

    def test_dotdot_through_missing_component_does_not_hide_mismatch(self):
        self.env["TEST_POSTGRES_VERSION"] = "postgres (PostgreSQL) 17.12"

        def populate(volume):
            (volume / "PG_VERSION").write_text("16\n")

        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/missing/..", populate
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Data directory uses PostgreSQL 16", result.stderr)
        self.assertIn("image runs PostgreSQL 17", result.stderr)
        self.assertNotIn("empty PGDATA", result.stdout)

    def test_nested_mount_is_not_the_volume(self):
        result = self.run_with_mounted_volume(
            "/var/lib/postgresql/data/nested",
            lambda volume: None,
            "mkdir -p /var/lib/elsewhere /var/lib/postgresql/data/nested\n"
            "mount --bind /var/lib/elsewhere /var/lib/postgresql/data/nested\n",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the mounted volume /var/lib/postgresql/data", result.stderr)
        self.assertIn("/var/lib/postgresql/data/nested", result.stderr)
        self.assertNotIn("empty PGDATA", result.stdout)


if __name__ == "__main__":
    unittest.main()
