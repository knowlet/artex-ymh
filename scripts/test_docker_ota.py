#!/usr/bin/env python3
"""Offline behavior regressions for the privileged OTA host boundary."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

import docker_ota as ota

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
SCHEMA = "c" * 64
REVISION = "d" * 40


class FakeRegistry:
    def resolve(self, channel):
        return {"channel": channel, "image": ota.REPOSITORY + "@" + NEW,
                "digest": NEW, "revision": REVISION, "schema": SCHEMA}


class FakeBackend:
    def __init__(self, config):
        self.config = config
        self.image = OLD
        self.schema = SCHEMA
        self.calls = []
        self.fail = None
        self.hold = None

    def event(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise ota.OTAError("injected " + name + " failure")

    def current(self):
        return {"image": self.image, "revision": "a" * 40, "schema": self.schema}

    def ensure_image(self, plan):
        self.event("pull")
        if self.hold:
            self.hold.wait(5)
        return NEW

    def preflight(self):
        self.event("preflight")
        return {"app": {"Id": "old-container"}, "postgres": {"Id": "database"},
                "old_image": self.image, "old_schema": self.schema}

    def assert_unchanged(self, record):
        self.event("unchanged")

    def stop(self, record):
        self.event("stop")

    def stop_failed(self, image):
        self.event("stop_failed")

    def backup(self, record, directory):
        self.event("backup")
        directory.mkdir(parents=True)
        return []

    def snapshot(self, record, image, retained, path):
        self.event("snapshot")
        return image

    def start(self, snapshot, image):
        self.event("start_new" if image == NEW else "start_old")
        self.image = image
        return "new-container" if image == NEW else "old-container"

    def health(self, container, image, pg):
        self.event("health_new" if image == NEW else "health_old")
        if pg != "database":
            raise AssertionError("database identity changed")
        if not self.config.marker.exists():
            raise AssertionError("maintenance removed before health")

    def persist(self, image, retained):
        self.event("persist")

    def image_info(self, image):
        return {"Id": image, "Config": {"Labels": {"org.opencontainers.image.revision": "a" * 40}}}

    def docker(self, *args):
        if args != ("start", "old-container"):
            raise AssertionError(args)
        self.event("restart_exact_old")


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = ota.Config(root, "test", [root / "compose.yml"], root / "state", root / "api.sock")
        self.backend = FakeBackend(self.config)
        self.verifier = mock.Mock()
        self.updater = ota.Updater(self.config, self.backend, FakeRegistry(), self.verifier)

    def apply(self):
        plan = self.updater.check("main")
        self.updater.submit(plan["plan_id"])
        self.wait()
        return self.updater.status()

    def wait(self):
        deadline = time.monotonic() + 5
        while self.updater.status().get("active") and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertFalse(self.updater.status().get("active"), "worker did not finish")

    def test_update_backup_before_start_and_release_after_health(self):
        status = self.apply()
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["current_image"], NEW)
        self.assertTrue(status["rollback_available"])
        self.assertFalse(self.config.marker.exists())
        self.assertLess(self.backend.calls.index("backup"), self.backend.calls.index("start_new"))
        self.assertLess(self.backend.calls.index("health_new"), self.backend.calls.index("persist"))
        self.assertEqual(self.verifier.call_count, 2)
        self.assertNotIn("previous", status)

    def test_no_docker_mutation_on_signature_failure(self):
        self.verifier.side_effect = ota.OTAError("signature rejected")
        with self.assertRaisesRegex(ota.OTAError, "signature"):
            self.updater.check("main")
        self.assertEqual(self.backend.calls, [])
        self.assertFalse(self.config.marker.exists())

    def test_reverify_failure_preserves_running_container(self):
        plan = self.updater.check("main")
        self.verifier.side_effect = ota.OTAError("verification unavailable")
        self.updater.submit(plan["plan_id"])
        self.wait()
        self.assertEqual(self.updater.status()["state"], "failed")
        self.assertNotIn("stop", self.backend.calls)
        self.assertFalse(self.config.marker.exists())

    def test_failed_download_does_not_stop_application(self):
        self.backend.fail = "pull"
        self.assertEqual(self.apply()["state"], "failed")
        self.assertNotIn("stop", self.backend.calls)

    def test_failed_preflight_does_not_stop_application(self):
        self.backend.fail = "preflight"
        self.assertEqual(self.apply()["state"], "failed")
        self.assertNotIn("stop", self.backend.calls)

    def test_config_drift_does_not_stop_application(self):
        self.backend.fail = "unchanged"
        self.assertEqual(self.apply()["state"], "failed")
        self.assertNotIn("stop", self.backend.calls)

    def test_stale_current_image_rejected_before_stop(self):
        plan = self.updater.check("main")
        self.backend.image = NEW
        self.updater.submit(plan["plan_id"])
        self.wait()
        self.assertEqual(self.updater.status()["state"], "failed")
        self.assertNotIn("stop", self.backend.calls)

    def test_backup_failure_restarts_exact_old_container(self):
        self.backend.fail = "backup"
        self.assertEqual(self.apply()["state"], "rolled_back")
        self.assertIn("restart_exact_old", self.backend.calls)
        self.assertNotIn("start_new", self.backend.calls)
        self.assertFalse(self.config.marker.exists())

    def test_same_fingerprint_readiness_failure_rolls_back(self):
        self.backend.fail = "health_new"
        self.assertEqual(self.apply()["state"], "rolled_back")
        self.assertEqual(self.backend.image, OLD)
        self.assertIn("health_old", self.backend.calls)
        self.assertFalse(self.config.marker.exists())

    def test_changed_fingerprint_never_auto_restores_database(self):
        self.backend.schema = "e" * 64
        self.backend.fail = "health_new"
        self.assertEqual(self.apply()["state"], "recovery_required")
        self.assertIn("stop_failed", self.backend.calls)
        self.assertNotIn("start_old", self.backend.calls)
        self.assertTrue(self.config.marker.exists())

    def test_unknown_legacy_fingerprint_is_not_rollback_compatible(self):
        self.backend.schema = ""
        self.backend.fail = "start_new"
        self.assertEqual(self.apply()["state"], "recovery_required")
        self.assertNotIn("start_old", self.backend.calls)

    def test_failed_recovery_keeps_maintenance(self):
        old_health = self.backend.health
        def health(*args):
            raise ota.OTAError("all readiness checks failed")
        self.backend.health = health
        self.assertEqual(self.apply()["state"], "recovery_required")
        self.assertTrue(self.config.marker.exists())
        self.backend.health = old_health

    def test_manual_rollback_requires_idle_gate_and_matching_fingerprint(self):
        self.apply()
        self.backend.schema = SCHEMA
        self.updater.submit(operation="rollback")
        self.wait()
        self.assertEqual(self.updater.status()["state"], "rolled_back")
        self.assertEqual(self.backend.image, OLD)

    def test_unknown_plan_and_expired_plan_never_create_marker(self):
        with self.assertRaises(ota.OTAError):
            self.updater.submit("foreign-plan")
        plan = self.updater.check("main")
        self.updater.plans[plan["plan_id"]]["expires_at"] = 0
        with self.assertRaises(ota.OTAError):
            self.updater.submit(plan["plan_id"])
        self.assertFalse(self.config.marker.exists())

    def test_unknown_channel_never_calls_registry(self):
        with self.assertRaises(ota.OTAError):
            self.updater.check("../../arbitrary")
        self.verifier.assert_not_called()

    def test_marker_is_durable_before_submission_returns_and_concurrency_rejected(self):
        self.backend.hold = threading.Event()
        self.addCleanup(self.backend.hold.set)
        plan = self.updater.check("main")
        status = self.updater.submit(plan["plan_id"])
        self.assertTrue(status["active"])
        self.assertTrue(self.config.marker.exists())
        self.assertTrue(ota.read_json(self.config.state_dir / "state.json")["active"])
        with self.assertRaises(ota.OTAError):
            self.updater.submit(plan["plan_id"])
        self.backend.hold.set()
        self.wait()

    def test_interrupted_update_survives_daemon_restart_fail_closed(self):
        ota.atomic_json(self.config.marker, {"job_id": "interrupted"})
        self.updater.state.update(state="starting", active=True)
        self.updater.save()
        restarted = ota.Updater(self.config, self.backend, FakeRegistry(), self.verifier)
        self.assertEqual(restarted.status()["state"], "recovery_required")
        with self.assertRaises(ota.OTAError):
            restarted.check("main")
        self.assertTrue(self.config.marker.exists())

    def test_terminal_journal_with_marker_still_requires_recovery(self):
        ota.atomic_json(self.config.marker, {"job_id": "interrupted"})
        self.updater.state.update(state="completed", active=False)
        self.updater.save()
        restarted = ota.Updater(self.config, self.backend, FakeRegistry(), self.verifier)
        self.assertEqual(restarted.status()["state"], "recovery_required")

    def test_state_and_marker_permissions(self):
        self.apply()
        self.assertEqual(self.config.state_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.config.state_dir / "state.json").stat().st_mode & 0o777, 0o600)


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = ota.Config(root, "test", [root / "compose.yml"], root / "state", root / "api.sock")

    def test_registry_resolves_channel_once_then_reads_pinned_child(self):
        calls = []
        manifest = {"digest": NEW, "manifests": [{"digest": OLD, "platform": {"os": "linux", "architecture": "amd64"}}]}
        config = {"os": "linux", "architecture": "amd64", "config": {"Labels": {
            "io.artex.ota.protocol": "1", "io.artex.ota.schema": SCHEMA,
            "org.opencontainers.image.revision": REVISION, "org.opencontainers.image.source": ota.SOURCE}}}
        def runner(args, **kwargs):
            calls.append(args)
            return json.dumps(manifest if len(calls) == 1 else config).encode()
        result = ota.Registry(self.config, runner).resolve("nightly")
        self.assertEqual(result["image"], ota.REPOSITORY + "@" + NEW)
        self.assertIn(ota.REPOSITORY + ":nightly", calls[0])
        self.assertIn(ota.REPOSITORY + "@" + OLD, calls[1])
        self.assertNotIn(ota.REPOSITORY + ":nightly", calls[1])

    def test_registry_rejects_missing_supported_platform(self):
        runner = lambda *a, **k: json.dumps({"digest": NEW, "manifests": []}).encode()
        with self.assertRaisesRegex(ota.OTAError, "linux/amd64"):
            ota.Registry(self.config, runner).resolve("main")

    def test_verifier_binds_full_identity_and_issuer(self):
        runner = mock.Mock(return_value=b"verified")
        ota.Verifier(self.config, runner)(ota.REPOSITORY + "@" + NEW)
        args = runner.call_args.args[0]
        self.assertIn(ota.IDENTITY, args)
        self.assertIn(ota.ISSUER, args)
        self.assertNotIn("--insecure-ignore-tlog", args)
        self.assertNotIn("--certificate-identity-regexp", args)

    def test_verifier_rejects_tags_foreign_repositories_and_shell_strings(self):
        runner = mock.Mock()
        verify = ota.Verifier(self.config, runner)
        for image in (ota.REPOSITORY + ":main", "ghcr.io/attacker/artex@" + NEW,
                      ota.REPOSITORY + "@" + NEW + "; touch /tmp/owned"):
            with self.subTest(image=image), self.assertRaises(ota.OTAError):
                verify(image)
        runner.assert_not_called()

    def test_snapshot_only_changes_application_and_escapes_literal_dollars(self):
        backend = ota.DockerBackend(self.config)
        original = {"name": "test", "services": {"postgres": {"image": "postgres:16-alpine"},
                    "artex": {"build": {"context": "/operator"}, "image": "local",
                              "environment": {"PASSWORD": "literal$HOME${SECRET}"},
                              "volumes": [{"type": "bind", "source": "/operator/data", "target": "/app/data"}]}}}
        record = {"config": copy.deepcopy(original)}
        path = self.config.project_dir / "snapshot.json"
        backend.snapshot(record, NEW, [], path)
        snapshot = ota.read_json(path)
        self.assertEqual(snapshot["services"]["postgres"], original["services"]["postgres"])
        self.assertEqual(snapshot["services"]["artex"]["environment"]["PASSWORD"], "literal$$HOME$${SECRET}")
        self.assertNotIn("build", snapshot["services"]["artex"])
        self.assertEqual(record["config"], original)

    def test_compose_uses_explicit_project_and_ordered_files(self):
        calls = []
        runner = lambda args, **kw: calls.append(args) or b""
        self.config.env_file = self.config.project_dir / ".env"
        self.config.compose_files.append(self.config.project_dir / "traefik.yml")
        ota.DockerBackend(self.config, runner).compose("ps", "-q", "artex")
        args = calls[0]
        self.assertIn("--project-name", args)
        self.assertIn("--project-directory", args)
        self.assertIn("--env-file", args)
        self.assertLess(args.index(str(self.config.compose_files[0])), args.index(str(self.config.compose_files[1])))
        self.assertEqual(args[-3:], ["ps", "-q", "artex"])

    def test_state_json_atomic_replace_does_not_follow_symlinks(self):
        victim = self.config.project_dir / "victim"
        victim.write_text("untouched")
        link = self.config.project_dir / "state.json"
        link.symlink_to(victim)
        ota.atomic_json(link, {"state": "idle"})
        self.assertEqual(victim.read_text(), "untouched")
        self.assertFalse(link.is_symlink())

    def test_runner_suppresses_sensitive_child_errors(self):
        with self.assertRaises(ota.OTAError) as error:
            ota.Runner()(["/bin/sh", "-c", "echo super-secret-password >&2; exit 19"])
        self.assertNotIn("super-secret", str(error.exception))
        self.assertIn("19", str(error.exception))


if __name__ == "__main__":
    unittest.main()
