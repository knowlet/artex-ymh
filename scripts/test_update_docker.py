#!/usr/bin/env python3
"""Execute the deployment scripts with disposable Docker/guard stand-ins."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DockerUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "scripts").mkdir()
        (self.root / "bin").mkdir()
        for script in ("update.sh", "install.sh"):
            shutil.copyfile(ROOT / script, self.root / script)
        self.original_env = "POSTGRES_PASSWORD=fixture-only\nARTEX_TAG=custom-existing\n"
        self.original_compose = (
            "services:\n  traefik:\n    image: traefik:v3.7\n"
            "  artex:\n    image: artex-ymh:local\n"
        )
        (self.root / ".env").write_text(self.original_env)
        (self.root / "docker-compose.yml").write_text(self.original_compose)
        self.log = self.root / "calls.jsonl"
        docker = self.root / "bin" / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys, time\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['TEST_CALLS'], 'a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "failure = os.environ.get('TEST_DOCKER_FAIL', '')\n"
            "if failure and args == json.loads(failure):\n"
            "    sys.exit(1)\n"
            "hold = os.environ.get('TEST_HOLD_BUILD', '')\n"
            "if hold and args == ['compose', 'build', 'artex']:\n"
            "    import fcntl\n"
            "    path = os.environ['TEST_CRITICAL']\n"
            "    def adjust(delta):\n"
            "        with open(path, 'a+') as handle:\n"
            "            fcntl.flock(handle, fcntl.LOCK_EX)\n"
            "            handle.seek(0)\n"
            "            current = int(handle.read().strip() or '0') + delta\n"
            "            peak_path = os.environ['TEST_PEAK']\n"
            "            peak = 0\n"
            "            if os.path.exists(peak_path):\n"
            "                peak = int(open(peak_path).read().strip() or '0')\n"
            "            if current > peak:\n"
            "                open(peak_path, 'w').write(str(current))\n"
            "            handle.seek(0)\n"
            "            handle.truncate()\n"
            "            handle.write(str(current))\n"
            "            fcntl.flock(handle, fcntl.LOCK_UN)\n"
            "    adjust(1)\n"
            "    time.sleep(float(hold))\n"
            "    adjust(-1)\n"
        )
        docker.chmod(0o755)
        (self.root / "scripts" / "check_postgres_version.sh").write_text(
            '#!/usr/bin/env bash\n'
            'printf \'["preflight"]\\n\' >> "$TEST_CALLS"\n'
            'exit "${TEST_PREFLIGHT_EXIT:-0}"\n'
        )
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.root / 'bin'}:{self.env['PATH']}",
            TEST_CALLS=str(self.log),
            TEST_PREFLIGHT_EXIT="0",
            TEST_DOCKER_FAIL="",
        )

    def run_script(self, name="update.sh"):
        result = subprocess.run(
            ["bash", str(self.root / name)],
            input="1\n",
            text=True,
            capture_output=True,
            env=self.env,
            cwd=self.root,
            timeout=10,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls

    def assert_configuration_unchanged(self):
        self.assertEqual((self.root / ".env").read_text(), self.original_env)
        self.assertEqual(
            (self.root / "docker-compose.yml").read_text(), self.original_compose
        )

    def test_update_builds_before_touching_services_and_limits_dependencies(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls,
            [
                ["compose", "version"],
                ["preflight"],
                ["compose", "build", "artex"],
                ["compose", "up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "postgres"],
                ["compose", "up", "-d", "--no-deps", "--no-build", "--pull", "never", "artex"],
            ],
        )
        self.assert_configuration_unchanged()

    def test_update_mismatch_aborts_before_build_or_service_recreation(self):
        self.env["TEST_PREFLIGHT_EXIT"] = "1"
        result, calls = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [["compose", "version"], ["preflight"]])
        self.assertNotIn("更新完成", result.stdout)
        self.assert_configuration_unchanged()

    def test_failed_build_leaves_running_services_alone(self):
        self.env["TEST_DOCKER_FAIL"] = json.dumps(["compose", "build", "artex"])
        result, calls = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("up" in call for call in calls))
        self.assertNotIn("更新完成", result.stdout)
        self.assert_configuration_unchanged()

    def test_unhealthy_postgres_does_not_start_artex(self):
        self.env["TEST_DOCKER_FAIL"] = json.dumps(
            ["compose", "up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "postgres"]
        )
        result, calls = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("up" in call and call[-1] == "artex" for call in calls))
        self.assertNotIn("更新完成", result.stdout)

    def test_failed_artex_start_does_not_report_success(self):
        self.env["TEST_DOCKER_FAIL"] = json.dumps(
            ["compose", "up", "-d", "--no-deps", "--no-build", "--pull", "never", "artex"]
        )
        result, _ = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("更新完成", result.stdout)

    def test_reinstall_mismatch_aborts_before_build_or_service_recreation(self):
        self.env["TEST_PREFLIGHT_EXIT"] = "1"
        result, calls = self.run_script("install.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [["compose", "version"], ["preflight"]])
        self.assertNotIn("启动完成", result.stdout)
        self.assert_configuration_unchanged()

    def test_install_checks_database_and_builds_before_startup(self):
        result, calls = self.run_script("install.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls,
            [
                ["compose", "version"],
                ["preflight"],
                ["compose", "build", "artex"],
                ["compose", "up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "postgres"],
                ["compose", "up", "-d", "--no-build"],
            ],
        )
        self.assert_configuration_unchanged()

    def test_concurrent_updates_do_not_overlap_image_build(self):
        self.env["TEST_HOLD_BUILD"] = "0.6"
        self.env["TEST_CRITICAL"] = str(self.root / "critical")
        self.env["TEST_PEAK"] = str(self.root / "peak")
        procs = [
            subprocess.Popen(
                ["bash", str(self.root / "update.sh")],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env,
                cwd=self.root,
            )
            for _ in range(2)
        ]
        outputs = [proc.communicate(input="1\n", timeout=15) for proc in procs]
        for proc, (stdout, stderr) in zip(procs, outputs):
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertIn("更新完成", stdout)
        peak = int((self.root / "peak").read_text().strip())
        self.assertEqual(peak, 1)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        sequence = [
            ["compose", "version"],
            ["preflight"],
            ["compose", "build", "artex"],
            ["compose", "up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "postgres"],
            ["compose", "up", "-d", "--no-deps", "--no-build", "--pull", "never", "artex"],
        ]
        self.assertEqual(calls, sequence + sequence)
        self.assert_configuration_unchanged()


if __name__ == "__main__":
    unittest.main()
