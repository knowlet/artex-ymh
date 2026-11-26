#!/usr/bin/env python3
"""Offline regressions for host recovery and preservation of runtime secrets.

Docker reads are simulated at the process boundary.  File copies, content hashes,
Compose overlays, permission checks, maintenance journals, and locks are real.
"""

import copy
import fcntl
import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

import docker_ota as ota


OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
UNKNOWN = "sha256:" + "c" * 64
SCHEMA = "d" * 64
REVISION = "e" * 40
JWT = b"jwt-preserved-key-material-32-characters\n"
GATE = b"gate-preserved-key-material-32-characters\n"


class ReadOnlyBackend(ota.DockerBackend):
    """Exercise real retention code while rejecting every Docker mutation."""

    def __init__(self, config):
        super().__init__(config)
        self.calls = []
        self.files = {"/app/jwt.key": JWT, "/app/gate.key": GATE}
        self.app = {"Id": "selected-container", "Image": NEW,
                    "State": {"Running": True},
                    "Config": {"Env": ["ARTEX_GATE=off"]}, "Mounts": []}

    def service(self, name):
        if name != "artex":
            raise AssertionError("unexpected service: " + name)
        self.calls.append(("service", name))
        return copy.deepcopy(self.app)

    def docker(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "cp" and len(args) == 3 and args[1].startswith(self.app["Id"] + ":"):
            path = args[1].split(":", 1)[1]
            if path not in self.files:
                raise ota.OTAError("runtime file missing")
            value = self.files[path]
            if callable(value):
                value(Path(args[2]))
            else:
                Path(args[2]).write_bytes(value)
            return b""
        if (args[:4] == ("exec", self.app["Id"], "python3", "-c") and len(args) == 5
                and 'Path("/app/config.json").exists()' in args[4]):
            return b"1\n" if "/app/config.json" in self.files else b"0\n"
        raise AssertionError("unexpected Docker mutation or unsupported read: " + repr(args))


class RecoveryBackend(ReadOnlyBackend):
    def __init__(self, config):
        super().__init__(config)
        self.fail = None

    def preflight(self):
        self.calls.append(("preflight",))
        self.assert_closed()
        overlay = ota.read_json(self.config.state_dir / "active-image.json")
        if overlay["services"]["artex"]["image"] != self.app["Image"]:
            raise AssertionError("preflight did not use the selected recovery image")
        if self.fail == "preflight":
            raise ota.OTAError("injected preflight failure")
        return {"postgres": {"Id": "same-postgres"}}

    def health(self, container, image, pg):
        self.calls.append(("health", container, image, pg))
        self.assert_closed()
        if (container, image, pg) != (self.app["Id"], self.app["Image"], "same-postgres"):
            raise AssertionError("recovery changed the selected container or PostgreSQL identity")
        if self.fail == "health":
            raise ota.OTAError("injected readiness failure")

    def assert_closed(self):
        if not self.config.marker.exists():
            raise AssertionError("recovery opened admission before readiness completed")

    def image_info(self, image):
        self.calls.append(("image_info", image))
        return {"Id": image, "Config": {"Labels": {
            "io.artex.ota.schema": SCHEMA,
            "org.opencontainers.image.revision": REVISION}}}


class HostTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="artex-ota-offline-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = ota.Config(self.root, "offline", [self.root / "compose.json"],
                                 self.root / "state", self.root / "api.sock")
        self.config.state_dir.mkdir(mode=0o700)

    def directory(self, name):
        path = self.config.state_dir / name
        path.mkdir(mode=0o700)
        return path

    def host_command(self, command, backend, *args):
        with mock.patch.object(ota, "deployment_locks", return_value=()), \
                mock.patch.object(ota, "DockerBackend", return_value=backend), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            command(self.config, *args)


class RuntimePreservationTests(HostTestCase):
    def setUp(self):
        super().setUp()
        self.backend = ReadOnlyBackend(self.config)

    def retain(self, name="backup", **kwargs):
        return self.backend.retain_runtime(self.backend.app, self.directory(name), **kwargs)

    def test_retained_files_survive_backup_removal_and_deduplicate(self):
        self.backend.app["Config"]["Env"] = ["ARTEX_GATE=on"]
        first = self.retain("first")
        second = self.retain("second")
        self.assertEqual(first, second)
        shutil.rmtree(self.config.state_dir / "first")
        shutil.rmtree(self.config.state_dir / "second")
        for mount, contents in zip(first, (JWT, GATE)):
            source = Path(mount["source"])
            self.assertEqual(source.parent, self.config.state_dir / "retained")
            self.assertEqual(source.name, hashlib.sha256(contents).hexdigest())
            self.assertEqual(source.read_bytes(), contents)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
            self.assertTrue(mount["read_only"])
            self.assertFalse(mount["bind"]["create_host_path"])
        self.assertEqual(stat.S_IMODE((self.config.state_dir / "retained").stat().st_mode), 0o700)

    def test_custom_key_directory_and_config_are_preserved_exactly(self):
        config = b'{"model":"example-$MODEL", "provider":"local"}\n'
        self.backend.app["Config"]["Env"] = ["ARTEX_GATE=off", "ARTEX_KEY_DIR= /run/secrets/ ",
                                                "ARTEX_CONFIG=/app/custom.json"]
        self.backend.files.update({"/run/secrets/jwt.key": JWT, "/app/custom.json": config})
        retained = self.retain()
        self.assertEqual([m["target"] for m in retained], ["/run/secrets/jwt.key", "/app/custom.json"])
        self.assertEqual([Path(m["source"]).read_bytes() for m in retained], [JWT, config])

    def test_config_path_uses_same_whitespace_normalization_as_application(self):
        self.backend.app["Config"]["Env"] += ["ARTEX_CONFIG= /app/config.json "]
        self.backend.files["/app/config.json"] = b'{"provider":"local"}\n'
        self.assertEqual(self.retain()[-1]["target"], "/app/config.json")

    def test_default_config_is_included_only_when_discovered(self):
        self.backend.files["/app/config.json"] = b'{"provider":"local"}\n'
        self.assertEqual([m["target"] for m in self.retain("without")], ["/app/jwt.key"])
        retained = self.retain("with", has_default_config=True)
        self.assertEqual([m["target"] for m in retained], ["/app/jwt.key", "/app/config.json"])

    def test_actual_gate_state_takes_precedence_over_environment_defaults(self):
        self.backend.app["Config"]["Env"] = []
        self.backend.files.pop("/app/gate.key")
        self.assertEqual([m["target"] for m in self.retain("closed", gate_enabled=False)], ["/app/jwt.key"])
        self.backend.app["Config"]["Env"] = ["ARTEX_GATE=off"]
        self.backend.files["/app/gate.key"] = GATE
        self.assertEqual([m["target"] for m in self.retain("enabled", gate_enabled=True)],
                         ["/app/jwt.key", "/app/gate.key"])

    def test_invalid_paths_are_rejected_before_docker_copy(self):
        for variable in ("ARTEX_KEY_DIR", "ARTEX_CONFIG"):
            for value in ("relative/path", "/app/../secrets", "/app:secrets"):
                with self.subTest(variable=variable, value=value):
                    self.backend.calls.clear()
                    self.backend.app["Config"]["Env"] = ["ARTEX_GATE=off", variable + "=" + value]
                    with self.assertRaises(ota.OTAError):
                        self.retain(variable + "-" + str(len(list(self.config.state_dir.iterdir()))))
                    self.assertEqual(self.backend.calls, [])

    def test_invalid_or_non_regular_runtime_files_never_become_mounts(self):
        outside = self.root / "outside-secret"
        outside.write_bytes(JWT)
        cases = {"short": b"x" * 31, "whitespace": b" " * 40,
                 "oversized": b"x" * (ota.MAX_JSON + 1),
                 "symlink": lambda path: path.symlink_to(outside),
                 "directory": lambda path: path.mkdir()}
        for name, value in cases.items():
            with self.subTest(name=name):
                self.backend.files["/app/jwt.key"] = value
                with self.assertRaises(ota.OTAError):
                    self.retain(name)
        self.assertFalse((self.config.state_dir / "retained").exists())
        self.assertEqual(outside.read_bytes(), JWT)

    def test_corrupted_content_addressed_file_is_not_overwritten(self):
        private = self.directory("retained")
        expected = private / hashlib.sha256(JWT).hexdigest()
        expected.write_bytes(b"unexpected existing contents")
        with self.assertRaisesRegex(ota.OTAError, "persisted runtime file changed"):
            self.retain()
        self.assertEqual(expected.read_bytes(), b"unexpected existing contents")

    def test_operator_owned_key_and_config_mounts_are_backed_up_without_replacement(self):
        config = b'{"model":"operator-managed"}\n'
        self.backend.app["Config"]["Env"] = ["ARTEX_GATE=off", "ARTEX_KEY_DIR=/run/secrets",
                                                "ARTEX_CONFIG=/etc/artex/config.json"]
        self.backend.files.update({"/run/secrets/jwt.key": JWT, "/etc/artex/config.json": config})
        self.backend.app["Mounts"] = [
            {"Type": "bind", "Source": "/operator/keys", "Destination": "/run/secrets", "RW": False},
            {"Type": "bind", "Source": "/operator/config.json", "Destination": "/etc/artex/config.json", "RW": True}]
        mounts = [{"type": "bind", "source": m["Source"], "target": m["Destination"],
                   "read_only": not m["RW"]} for m in self.backend.app["Mounts"]]
        directory = self.directory("backup")
        retained = self.backend.retain_runtime(self.backend.app, directory)
        self.assertEqual(retained, [])
        self.assertEqual((directory / "retained-0").read_bytes(), JWT)
        self.assertEqual((directory / "retained-1").read_bytes(), config)
        path = self.root / "snapshot.json"
        self.backend.snapshot({"config": {"services": {"artex": {"volumes": mounts}}}}, NEW, retained, path)
        self.assertEqual(ota.read_json(path)["services"]["artex"]["volumes"], mounts)

    def test_existing_helper_managed_key_mount_remains_in_managed_overlay(self):
        first = self.retain("before")
        self.backend.app["Mounts"] = [{"Type": "bind", "Source": first[0]["source"],
                                        "Destination": "/app/jwt.key", "RW": False}]
        retained = self.retain("after")
        self.assertEqual(retained, first)
        self.backend.persist(NEW, retained)
        overlay = ota.read_json(self.config.state_dir / "active-image.json")
        self.assertEqual(overlay["services"]["artex"]["volumes"], first)

    def test_sibling_mount_and_tmpfs_do_not_count_as_durable_runtime_storage(self):
        self.backend.app["Config"]["Env"] = ["ARTEX_GATE=off", "ARTEX_KEY_DIR=/run/secrets"]
        self.backend.files["/run/secrets/jwt.key"] = JWT
        self.backend.app["Mounts"] = [
            {"Type": "bind", "Source": "/operator/keys", "Destination": "/run/secrets-other", "RW": False},
            {"Type": "tmpfs", "Source": "", "Destination": "/run/secrets", "RW": True}]
        retained = self.retain()
        self.assertEqual([m["target"] for m in retained], ["/run/secrets/jwt.key"])
        self.assertEqual(Path(retained[0]["source"]).read_bytes(), JWT)

    def test_snapshot_replaces_key_mount_without_recreating_postgres_configuration(self):
        retained = self.retain()
        postgres = {"image": "postgres:16-alpine", "volumes": [{"type": "volume", "source": "pgdata",
                                                               "target": "/var/lib/postgresql/data"}]}
        original = {"services": {"artex": {"build": {"context": "."}, "image": OLD,
            "environment": {"TOKEN": "literal$value"}, "volumes": [
                {"type": "bind", "source": "/old/key", "target": "/app/jwt.key"},
                {"type": "volume", "source": "data", "target": "/app/data"}]},
            "postgres": postgres}, "volumes": {"pgdata": {}, "data": {}}}
        record = {"config": copy.deepcopy(original)}
        path = self.root / "snapshot.json"
        self.backend.snapshot(record, NEW, retained, path)
        snapshot = ota.read_json(path)
        self.assertEqual(record["config"], original)
        self.assertEqual(snapshot["services"]["postgres"], postgres)
        app = snapshot["services"]["artex"]
        self.assertNotIn("build", app)
        self.assertEqual((app["image"], app["pull_policy"]), (NEW, "never"))
        self.assertEqual(app["environment"]["TOKEN"], "literal$$value")
        keys = [m for m in app["volumes"] if m["target"] == "/app/jwt.key"]
        self.assertEqual(keys, retained)
        self.backend.persist(NEW, retained)
        overlay = ota.read_json(self.config.state_dir / "active-image.json")
        self.assertEqual(overlay["services"]["artex"]["volumes"], retained)


class PrepareTests(HostTestCase):
    def test_prepare_only_reads_docker_and_preserves_existing_keys_and_config(self):
        backend = ReadOnlyBackend(self.config)
        backend.files["/app/config.json"] = b'{"model":"local"}\n'
        self.host_command(ota.prepare, backend)
        overlay = ota.read_json(self.config.state_dir / "active-image.json")
        self.assertEqual(set(overlay["services"]["artex"]), {"volumes"})
        mounts = overlay["services"]["artex"]["volumes"]
        self.assertEqual([m["target"] for m in mounts], ["/app/jwt.key", "/app/config.json"])
        for mount in mounts:
            self.assertEqual(Path(mount["source"]).parent, self.config.state_dir / "retained")
        self.assertFalse(self.config.marker.exists())
        self.assertEqual(ota.read_json(self.config.state_dir / "state.json")["state"], "idle")
        self.assertEqual([call[0] for call in backend.calls], ["service", "exec", "cp", "cp"])

    def test_prepare_refuses_to_replace_managed_or_interrupted_state(self):
        backend = ReadOnlyBackend(self.config)
        for phase in ("completed", "recovery_required"):
            with self.subTest(phase=phase):
                ota.atomic_json(self.config.state_dir / "state.json", {"state": phase, "active": False})
                with self.assertRaisesRegex(ota.OTAError, "already managed"):
                    self.host_command(ota.prepare, backend)
        ota.atomic_json(self.config.state_dir / "state.json", {"state": "idle", "active": False})
        old_overlay = {"services": {"artex": {"image": OLD}}}
        ota.atomic_json(self.config.state_dir / "active-image.json", old_overlay)
        with self.assertRaisesRegex(ota.OTAError, "already managed"):
            self.host_command(ota.prepare, backend)
        self.assertEqual(ota.read_json(self.config.state_dir / "active-image.json"), old_overlay)
        self.assertEqual(backend.calls, [])

    def test_prepare_requires_running_application_and_all_required_files(self):
        backend = ReadOnlyBackend(self.config)
        backend.app["State"]["Running"] = False
        with self.assertRaisesRegex(ota.OTAError, "start the existing application"):
            self.host_command(ota.prepare, backend)
        backend.app["State"]["Running"] = True
        backend.files.pop("/app/jwt.key")
        with self.assertRaisesRegex(ota.OTAError, "runtime file missing"):
            self.host_command(ota.prepare, backend)
        self.assertFalse((self.config.state_dir / "active-image.json").exists())


class RecoveryTests(HostTestCase):
    def setUp(self):
        super().setUp()
        self.backend = RecoveryBackend(self.config)
        self.previous = {"services": {"artex": {"image": OLD, "pull_policy": "never",
                                                "volumes": []}}}
        ota.atomic_json(self.config.state_dir / "active-image.json", self.previous)
        ota.atomic_json(self.config.state_dir / "state.json", {
            "state": "recovery_required", "active": False, "source_image": OLD,
            "target_image": NEW, "current_image": OLD, "job_id": "interrupted-job",
            "operation": "apply", "target_digest": NEW, "target_revision": REVISION,
            "channel": "main", "previous": {"image": OLD, "schema": SCHEMA}, "history": []})
        ota.atomic_json(self.config.marker, {"job_id": "interrupted-job"}, 0o644)

    def recover(self, image=NEW):
        self.host_command(ota.recover, self.backend, image)

    def test_recovery_checks_exact_restored_image_before_reopening_admission(self):
        retained = self.directory("retained") / hashlib.sha256(JWT).hexdigest()
        retained.write_bytes(JWT)
        self.backend.app["Mounts"] = [
            {"Type": "bind", "Source": str(retained), "Destination": "/app/jwt.key", "RW": False},
            {"Type": "bind", "Source": str(retained), "Destination": "/app/writable.key", "RW": True},
            {"Type": "bind", "Source": str(self.config.state_dir / "backups" / "old-key"),
             "Destination": "/app/backup.key", "RW": False},
            {"Type": "volume", "Source": "/var/lib/docker/volumes/data/_data",
             "Destination": "/app/data", "RW": True}]
        self.recover()
        self.assertEqual(self.backend.calls, [("service", "artex"), ("preflight",),
            ("health", "selected-container", NEW, "same-postgres"), ("image_info", NEW)])
        state = ota.read_json(self.config.state_dir / "state.json")
        self.assertEqual((state["state"], state["active"], state["current_image"]), ("completed", False, NEW))
        self.assertEqual((state["current_schema"], state["current_revision"]), (SCHEMA, REVISION))
        self.assertEqual(state["previous"], {})
        self.assertEqual(state["history"][-1]["job_id"], "interrupted-job")
        self.assertFalse(self.config.marker.exists())
        overlay = ota.read_json(self.config.state_dir / "active-image.json")["services"]["artex"]
        self.assertEqual((overlay["image"], overlay["pull_policy"]), (NEW, "never"))
        self.assertEqual([m["target"] for m in overlay["volumes"]], ["/app/jwt.key"])

    def test_recovery_rejects_unrecorded_or_mutable_image_references(self):
        for image in (UNKNOWN, "latest", ota.REPOSITORY + "@" + NEW, NEW.upper()):
            with self.subTest(image=image):
                with self.assertRaisesRegex(ota.OTAError, "exact image ID recorded"):
                    self.recover(image)
                self.assertTrue(self.config.marker.exists())
                self.assertEqual(ota.read_json(self.config.state_dir / "active-image.json"), self.previous)
        self.assertEqual(self.backend.calls, [])

    def test_recovery_refuses_stopped_or_different_container(self):
        for image, running in ((OLD, True), (NEW, False)):
            with self.subTest(image=image, running=running):
                self.backend.app.update(Image=image, State={"Running": running})
                with self.assertRaisesRegex(ota.OTAError, "restore and start"):
                    self.recover()
                self.assertTrue(self.config.marker.exists())
                self.assertEqual(ota.read_json(self.config.state_dir / "active-image.json"), self.previous)

    def test_preflight_or_readiness_failure_restores_overlay_and_keeps_admission_closed(self):
        for failure in ("preflight", "health"):
            with self.subTest(failure=failure):
                self.backend.fail = failure
                with self.assertRaises(ota.OTAError):
                    self.recover()
                self.assertEqual(ota.read_json(self.config.state_dir / "active-image.json"), self.previous)
                self.assertTrue(self.config.marker.exists())
                state = ota.read_json(self.config.state_dir / "state.json")
                self.assertEqual(state["state"], "recovery_required")
                self.assertEqual(state["history"], [])

    def test_running_daemon_lock_prevents_recovery_before_any_docker_read(self):
        lock = os.open(self.config.state_dir / "daemon.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original = (self.config.state_dir / "state.json").read_bytes()
        with mock.patch.object(ota, "DockerBackend") as backend:
            with self.assertRaisesRegex(ota.OTAError, "another updater is using"):
                ota.recover(self.config, NEW)
            backend.assert_not_called()
        self.assertEqual((self.config.state_dir / "state.json").read_bytes(), original)
        self.assertTrue(self.config.marker.exists())


class AuditResetTests(HostTestCase):
    def test_new_job_cannot_reuse_previous_target_image_or_backup_in_its_audit(self):
        backend = RecoveryBackend(self.config)
        backend.app["Image"] = OLD
        registry = mock.Mock()
        registry.resolve.return_value = {"channel": "main", "image": ota.REPOSITORY + "@" + NEW,
                                         "digest": NEW, "revision": REVISION, "schema": SCHEMA}
        updater = ota.Updater(self.config, backend=backend, registry=registry, verifier=mock.Mock())
        updater.state.update(target_image=UNKNOWN, backup="/previous/job/backup")
        plan = updater.check("main")
        with mock.patch.object(ota.threading, "Thread") as thread:
            status = updater.submit(plan["plan_id"])
            thread.return_value.start.assert_called_once_with()
        self.assertEqual(status["state"], "queued")
        self.assertIsNone(status["target_image"])
        self.assertIsNone(status["backup"])
        self.assertEqual(status["source_image"], OLD)
        self.assertEqual((status["target_digest"], status["target_revision"], status["channel"]),
                         (NEW, REVISION, "main"))
        self.assertEqual(ota.read_json(self.config.marker)["job_id"], status["job_id"])


if __name__ == "__main__":
    unittest.main()
