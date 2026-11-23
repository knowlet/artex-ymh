#!/usr/bin/env python3
"""Execute the deployment scripts with disposable Docker/guard stand-ins."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
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
            "if args == ['info', '--format', '{{.ID}}']:\n"
            "    sys.stdout.write(os.environ.get('TEST_DOCKER_ID', 'testdaemon') + '\\n')\n"
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
        shutil.copyfile(
            ROOT / "scripts" / "docker_update_lock.sh",
            self.root / "scripts" / "docker_update_lock.sh",
        )
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.root / 'bin'}:{self.env['PATH']}",
            TEST_CALLS=str(self.log),
            TEST_PREFLIGHT_EXIT="0",
            TEST_DOCKER_FAIL="",
            TMPDIR=str(self.root / "tmp"),
            HOME=str(self.root / "home"),
            # Present, and different from HOME, so a lock that still follows
            # XDG_STATE_HOME fails the shared-lock tests below.
            XDG_STATE_HOME=str(self.root / "ignored-xdg"),
            TEST_DOCKER_ID=self.root.name,
        )
        (self.root / "tmp").mkdir()
        self.addCleanup(
            shutil.rmtree,
            Path("/tmp/artex-ymh-update-locks") / self.root.name,
            True,
        )

    def run_script(self, name="update.sh", root=None, env=None, timeout=10):
        root = root or self.root
        env = env or self.env
        result = subprocess.run(
            ["bash", str(root / name)],
            input="1\n",
            text=True,
            capture_output=True,
            env=env,
            cwd=root,
            timeout=timeout,
        )
        text = self.log.read_text() if self.log.exists() else ""
        calls = [json.loads(line) for line in text.splitlines()]
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
                ["info", "--format", "{{.ID}}"],
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
        self.assertEqual(
            calls,
            [["info", "--format", "{{.ID}}"], ["compose", "version"], ["preflight"]],
        )
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
        self.assertEqual(
            calls,
            [["compose", "version"], ["info", "--format", "{{.ID}}"], ["preflight"]],
        )
        self.assertNotIn("启动完成", result.stdout)
        self.assert_configuration_unchanged()

    def test_install_checks_database_and_builds_before_startup(self):
        result, calls = self.run_script("install.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls,
            [
                ["compose", "version"],
                ["info", "--format", "{{.ID}}"],
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
        for proc in procs:
            proc.stdin.write("1\n")
            proc.stdin.flush()
        outputs = [proc.communicate(timeout=15) for proc in procs]
        for proc, (stdout, stderr) in zip(procs, outputs):
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertIn("更新完成", stdout)
        peak = int((self.root / "peak").read_text().strip())
        self.assertEqual(peak, 1)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        # docker info runs before the lock, so the two identity reads can
        # precede either build. The build-and-deploy calls stay serialized.
        info = ["info", "--format", "{{.ID}}"]
        body = [
            ["compose", "version"],
            ["preflight"],
            ["compose", "build", "artex"],
            ["compose", "up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "postgres"],
            ["compose", "up", "-d", "--no-deps", "--no-build", "--pull", "never", "artex"],
        ]
        self.assertEqual([call for call in calls if call == info], [info, info])
        self.assertEqual([call for call in calls if call != info], body + body)
        self.assert_configuration_unchanged()

    def shell_out(self, script, arg):
        return subprocess.check_output(
            ["bash", "-c", script, "bash", arg], text=True
        ).strip()

    def daemon_lock_path(self, env):
        daemon = env.get("TEST_DOCKER_ID", "testdaemon")
        return Path("/tmp/artex-ymh-update-locks") / daemon / "docker-update.lock"

    def legacy_lock_path(self, env, checkout):
        key = self.shell_out(
            "cd \"$1\" && pwd -P | cksum | awk '{print $1}'", str(checkout)
        )
        return Path(env["TMPDIR"]) / f"artex-docker-update.{key}.lock"

    def write_checkout(self, root):
        root.mkdir(parents=True, exist_ok=True)
        (root / "scripts").mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "update.sh", root / "update.sh")
        (root / ".env").write_text(self.original_env)
        (root / "docker-compose.yml").write_text(self.original_compose)
        (root / "scripts" / "check_postgres_version.sh").write_text(
            "#!/usr/bin/env bash\n"
            "printf '[\"preflight\"]\\n' >> \"$TEST_CALLS\"\n"
            "exit \"${TEST_PREFLIGHT_EXIT:-0}\"\n"
        )
        shutil.copyfile(
            ROOT / "scripts" / "docker_update_lock.sh",
            root / "scripts" / "docker_update_lock.sh",
        )

    def test_different_checkouts_share_one_daemon_image_lock(self):
        other = self.root / "other-checkout"
        self.write_checkout(other)
        self.env["TEST_HOLD_BUILD"] = "0.6"
        self.env["TEST_CRITICAL"] = str(self.root / "critical")
        self.env["TEST_PEAK"] = str(self.root / "peak")
        procs = [
            subprocess.Popen(
                ["bash", str(checkout / "update.sh")],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env,
                cwd=checkout,
            )
            for checkout in (self.root, other)
        ]
        for proc in procs:
            proc.stdin.write("1\n")
            proc.stdin.flush()
        outputs = [proc.communicate(timeout=15) for proc in procs]
        for proc, (stdout, stderr) in zip(procs, outputs):
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertIn("更新完成", stdout)
        peak = int((self.root / "peak").read_text().strip())
        self.assertEqual(peak, 1)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        info = ["info", "--format", "{{.ID}}"]
        body = [
            ["compose", "version"],
            ["preflight"],
            ["compose", "build", "artex"],
            ["compose", "up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "postgres"],
            ["compose", "up", "-d", "--no-deps", "--no-build", "--pull", "never", "artex"],
        ]
        self.assertEqual([call for call in calls if call == info], [info, info])
        self.assertEqual([call for call in calls if call != info], body + body)

    def test_lock_file_is_private_and_existing_contents_survive(self):
        lock = self.daemon_lock_path(self.env)
        lock.parent.mkdir(parents=True)
        lock.parent.chmod(0o755)
        lock.write_text("keep-new\n")
        legacy = self.legacy_lock_path(self.env, self.root)
        legacy.write_text("keep-old\n")
        result, _ = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(lock.read_text(), "keep-new\n")
        self.assertEqual(legacy.read_text(), "keep-old\n")
        self.assertFalse(lock.is_symlink())
        self.assertEqual(lock.parent.stat().st_mode & 0o777, 0o777)
        self.assertEqual(lock.parent.stat().st_uid, os.getuid())
        self.assertEqual(list(Path(self.env["TMPDIR"]).glob("artex-docker-update*")), [legacy])

    def test_upgrade_backups_are_excluded_from_the_build_context(self):
        import re
        guide = (ROOT / "docs" / "POSTGRES-UPGRADE.md").read_text()
        dirs = set(re.findall(r'backup_dir="\$PWD/([^/"]+)/', guide))
        self.assertEqual(dirs, {"backups"})
        patterns = [
            line.strip().strip("/")
            for line in (ROOT / ".dockerignore").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertIn("backups", patterns)

    def test_lock_directory_checks_do_not_need_gnu_stat(self):
        # macOS stat is BSD stat, which has no -c option.
        bsd_stat = self.root / "bin" / "stat"
        bsd_stat.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = -c ]; then\n"
            "  echo 'stat: illegal option -- c' >&2\n"
            "  exit 1\n"
            "fi\n"
            "exec /usr/bin/stat \"$@\"\n"
        )
        bsd_stat.chmod(0o755)
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["preflight"], calls)
        lock_dir = self.daemon_lock_path(self.env).parent
        self.assertEqual(lock_dir.stat().st_mode & 0o777, 0o777)

    def test_lock_refuses_symlink_without_truncating_the_target(self):
        lock = self.daemon_lock_path(self.env)
        lock.parent.mkdir(parents=True)
        lock.parent.chmod(0o700)
        victim = self.root / "victim"
        victim.write_text("precious")
        lock.symlink_to(victim)
        legacy = self.legacy_lock_path(self.env, self.root)
        legacy_victim = self.root / "legacy-victim"
        legacy_victim.write_text("legacy-precious")
        legacy.symlink_to(legacy_victim)
        result, calls = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("符号链接", result.stderr)
        self.assertEqual(victim.read_text(), "precious")
        self.assertEqual(legacy_victim.read_text(), "legacy-precious")
        self.assertFalse(any(call[:2] == ["compose", "build"] for call in calls))

    def path_without_flock(self):
        bindir = self.root / "path-no-flock"
        bindir.mkdir(exist_ok=True)
        for name in (
            "bash",
            "awk",
            "cksum",
            "stat",
            "find",
            "id",
            "chmod",
            "date",
            "tr",
            "mkdir",
            "cat",
            "rm",
            "sleep",
            "readlink",
            "dirname",
            "basename",
        ):
            source = shutil.which(name)
            dest = bindir / name
            if source and not dest.exists():
                dest.symlink_to(source)
        return f"{self.root / 'bin'}:{bindir}"

    def dead_pid(self):
        proc = subprocess.Popen(["true"])
        proc.wait()
        return proc.pid

    def test_directory_lock_stale_takeover_rechecks_before_removing(self):
        env = self.env.copy()
        env["PATH"] = self.path_without_flock()
        hold = Path(str(self.daemon_lock_path(env)) + ".d")
        hold.parent.mkdir(parents=True)
        hold.parent.chmod(0o700)
        hold.mkdir()
        (hold / "pid").write_text(f"{self.dead_pid()}\n")
        # A live process standing in for the waiter that won the stale lock.
        winner = subprocess.Popen(["sleep", "30"])
        self.addCleanup(winner.kill)
        # The live owner publishes starttime before its PID is visible. The
        # stub reveals that PID only after the first stale read.
        winner_stat = Path(f"/proc/{winner.pid}/stat").read_text().split(")", 1)[1].split()
        (hold / "starttime").write_text(winner_stat[19] + "\n")
        (hold / "started").write_text(f"{int(time.time())}\n")
        # The first read of the lock PID returns the dead owner; right after
        # it, the other waiter takes the lock over (its PID is now there).
        stub = self.root / "bin" / "cat"
        stub.write_text(
            "#!" + shutil.which("bash") + "\n"
            'case "${1:-}" in *.lock.d/pid)\n'
            '  if [ ! -e "$TEST_RACE_MARK" ]; then\n'
            '    : > "$TEST_RACE_MARK"\n'
            f'    {shutil.which("cat")} "$1"\n'
            '    printf \'%s\\n\' "$TEST_RACE_WINNER" > "$1"\n'
            "    exit 0\n"
            "  fi;;\n"
            "esac\n"
            f'exec {shutil.which("cat")} "$@"\n'
        )
        stub.chmod(0o755)
        env["TEST_RACE_MARK"] = str(self.root / "race-mark")
        env["TEST_RACE_WINNER"] = str(winner.pid)
        proc = subprocess.Popen(
            ["bash", str(self.root / "update.sh")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, cwd=self.root,
        )
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        proc.stdin.write("1\n")
        proc.stdin.flush()
        deadline = time.monotonic() + 2.5
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.05)
        calls = self.log.read_text() if self.log.exists() else ""
        self.assertTrue((self.root / "race-mark").exists(), "stale PID was never read")
        self.assertNotIn('"build"', calls, "took a live lock away from its owner")
        self.assertEqual((hold / "pid").read_text().strip(), str(winner.pid))
        # Once the owner releases its lock, the waiter proceeds normally.
        shutil.rmtree(hold)
        stdout, stderr = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, 0, stderr)
        self.assertIn("更新完成", stdout)
        self.assertEqual(list(hold.parent.glob("*.reap")), [])

    def test_directory_lock_left_by_dead_owner_is_reaped(self):
        env = self.env.copy()
        env["PATH"] = self.path_without_flock()
        hold = Path(str(self.daemon_lock_path(env)) + ".d")
        hold.parent.mkdir(parents=True)
        hold.parent.chmod(0o700)
        hold.mkdir()
        (hold / "pid").write_text(f"{self.dead_pid()}\n")
        # A reaper killed mid-removal is cleared the same way.
        reaper = Path(str(hold) + ".reap")
        reaper.mkdir()
        (reaper / "pid").write_text(f"{self.dead_pid()}\n")
        result, calls = self.run_script(env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call[:3] == ["compose", "build", "artex"] for call in calls))
        self.assertFalse(hold.exists())
        self.assertFalse(reaper.exists())

    def test_directory_lock_signals_exit_before_compose_up(self):
        env = self.env.copy()
        env["PATH"] = self.path_without_flock()
        env["TEST_HOLD_BUILD"] = "1.5"
        env["TEST_CRITICAL"] = str(self.root / "critical")
        env["TEST_PEAK"] = str(self.root / "peak")
        for sig, status in ((signal.SIGTERM, 143), (signal.SIGINT, 130)):
            with self.subTest(signal=sig):
                self.log.write_text("")
                proc = subprocess.Popen(
                    ["bash", str(self.root / "update.sh")],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                    cwd=self.root,
                )
                proc.stdin.write("1\n")
                proc.stdin.flush()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if self.log.exists() and '"build"' in self.log.read_text():
                        break
                    if proc.poll() is not None:
                        break
                    time.sleep(0.05)
                proc.send_signal(sig)
                stdout, stderr = proc.communicate(timeout=10)
                self.assertEqual(proc.returncode, status, stderr)
                self.assertNotIn("更新完成", stdout)
                calls = [json.loads(line) for line in self.log.read_text().splitlines()]
                self.assertTrue(any(call[:3] == ["compose", "build", "artex"] for call in calls))
                self.assertFalse(any("up" in call for call in calls), calls)
                self.assertFalse(Path(str(self.daemon_lock_path(env)) + ".d").exists())

    def hold_build(self, env):
        env = env.copy()
        env["TEST_HOLD_BUILD"] = "0.6"
        env["TEST_CRITICAL"] = str(self.root / "critical")
        env["TEST_PEAK"] = str(self.root / "peak")
        return env

    def assert_serialized(self, envs, scripts):
        procs = [
            subprocess.Popen(
                ["bash", str(self.root / script)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=self.root,
            )
            for env, script in zip(envs, scripts)
        ]
        for proc in procs:
            proc.stdin.write("1\n")
            proc.stdin.flush()
        outputs = [proc.communicate(timeout=20) for proc in procs]
        for proc, (stdout, stderr) in zip(procs, outputs):
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertTrue("更新完成" in stdout or "启动完成" in stdout, stdout)
        peak = int((self.root / "peak").read_text().strip())
        self.assertEqual(peak, 1)

    def test_update_script_stays_executable(self):
        recorded = subprocess.check_output(
            ["git", "ls-files", "-s", "--", "update.sh"],
            cwd=ROOT,
            text=True,
        )
        self.assertTrue(recorded.startswith("100755 "), recorded)

    def test_flock_and_directory_callers_share_one_lock(self):
        with_flock = self.hold_build(self.env)
        without = self.hold_build(self.env)
        without["PATH"] = self.path_without_flock()
        self.env = with_flock
        self.assert_serialized((with_flock, without), ("update.sh", "update.sh"))

    def test_default_socket_spelling_shares_the_lock(self):
        plain = self.hold_build(self.env)
        explicit = self.hold_build(self.env)
        explicit["DOCKER_HOST"] = "unix:///var/run/docker.sock/"
        self.env = plain
        self.assert_serialized((plain, explicit), ("update.sh", "update.sh"))

    def test_xdg_state_home_does_not_split_the_lock(self):
        first = self.hold_build(self.env)
        second = self.hold_build(self.env)
        second["XDG_STATE_HOME"] = str(self.root / "other-xdg")
        self.env = first
        self.assert_serialized((first, second), ("update.sh", "update.sh"))

    def test_install_and_update_share_the_image_lock(self):
        env = self.hold_build(self.env)
        self.env = env
        self.assert_serialized((env, env), ("update.sh", "install.sh"))

    def test_reaper_without_pid_stops_instead_of_spinning(self):
        hold = Path(str(self.daemon_lock_path(self.env)) + ".d")
        hold.parent.mkdir(parents=True)
        hold.parent.chmod(0o700)
        hold.mkdir()
        (hold / "pid").write_text(f"{self.dead_pid()}\n")
        reaper = Path(str(hold) + ".reap")
        reaper.mkdir()
        started = time.monotonic()
        result, calls = self.run_script(timeout=20)
        elapsed = time.monotonic() - started
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("没有进程号", result.stderr)
        self.assertGreaterEqual(elapsed, 3)
        self.assertLess(elapsed, 15)
        self.assertTrue(reaper.is_dir())
        self.assertFalse((reaper / "pid").exists())
        self.assertFalse(any(call[:2] == ["compose", "build"] for call in calls))

    def test_different_homes_and_host_spellings_share_one_daemon_lock(self):
        first = self.hold_build(self.env)
        second = self.hold_build(self.env)
        second["HOME"] = str(self.root / "other-home")
        first["DOCKER_HOST"] = "unix://localhost/var/run/docker.sock"
        second["DOCKER_HOST"] = "tcp://127.0.0.1:2375"
        second["DOCKER_CONTEXT"] = "remote"
        self.env = first
        self.assert_serialized((first, second), ("update.sh", "update.sh"))
        lock = self.daemon_lock_path(first)
        self.assertEqual(lock, self.daemon_lock_path(second))
        self.assertFalse(str(lock).startswith(str(first["HOME"])))
        self.assertFalse(str(lock).startswith(str(second["HOME"])))

    def test_different_daemon_ids_do_not_share_the_lock(self):
        first = self.hold_build(self.env)
        second = self.hold_build(self.env)
        second["TEST_DOCKER_ID"] = self.root.name + "other"
        self.addCleanup(
            shutil.rmtree,
            Path("/tmp/artex-ymh-update-locks") / second["TEST_DOCKER_ID"],
            True,
        )
        self.env = first
        procs = [
            subprocess.Popen(
                ["bash", str(self.root / "update.sh")],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=self.root,
            )
            for env in (first, second)
        ]
        for proc in procs:
            proc.stdin.write("1\n")
            proc.stdin.flush()
        outputs = [proc.communicate(timeout=15) for proc in procs]
        for proc, (stdout, stderr) in zip(procs, outputs):
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertIn("更新完成", stdout)
        self.assertEqual(int((self.root / "peak").read_text().strip()), 2)
        self.assertNotEqual(self.daemon_lock_path(first), self.daemon_lock_path(second))

    def test_reused_pid_does_not_block_the_directory_lock(self):
        env = self.env.copy()
        env["PATH"] = self.path_without_flock()
        hold = Path(str(self.daemon_lock_path(env)) + ".d")
        hold.parent.mkdir(parents=True)
        hold.parent.chmod(0o777)
        hold.mkdir()
        holder = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: holder.poll() is None and holder.kill())
        (hold / "pid").write_text(f"{holder.pid}\n")
        (hold / "starttime").write_text("1\n")
        (hold / "started").write_text(f"{int(time.time())}\n")
        result, calls = self.run_script(env=env, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call[:3] == ["compose", "build", "artex"] for call in calls))
        self.assertFalse(hold.exists() and (hold / "pid").read_text().strip() == str(holder.pid))

    def test_lock_directory_without_pid_stops(self):
        hold = Path(str(self.daemon_lock_path(self.env)) + ".d")
        hold.parent.mkdir(parents=True)
        hold.parent.chmod(0o700)
        hold.mkdir()
        result, calls = self.run_script(timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("更新锁目录没有进程号", result.stderr)
        self.assertTrue(hold.is_dir())
        self.assertFalse(any(call[:2] == ["compose", "build"] for call in calls))


if __name__ == "__main__":
    unittest.main()
