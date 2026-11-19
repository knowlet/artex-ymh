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
            "with open(os.environ['TEST_CALLS'], 'a') as log:\n"
            "    log.write(json.dumps(args[:-1]) + '\\n')\n"
            "prefix = ['compose', 'run', '--rm', '--no-deps', '-T', '--entrypoint', 'sh', 'postgres', '-ec']\n"
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
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/check_postgres_version.sh")],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=10,
        )
        after = {p.name: p.read_bytes() for p in self.data.iterdir() if p.is_file()}
        self.assertEqual(before, after, "preflight changed the data directory")
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 1, "preflight invoked an extra container operation")
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


if __name__ == "__main__":
    unittest.main()
