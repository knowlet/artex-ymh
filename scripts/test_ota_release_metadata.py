from pathlib import Path
import subprocess
import tempfile
import unittest

from ota_release_metadata import REPOSITORY, resolve, schema_fingerprint

SHA = "1" * 40
TAG_SHA = "2" * 40


class ReleaseResolutionTests(unittest.TestCase):
    def resolve(self, event="push", inputs=None, **kwargs):
        return resolve(event, {"inputs": inputs or {}}, kwargs.pop("ref", "refs/heads/main"),
                       kwargs.pop("sha", SHA), repository=kwargs.pop("repository", REPOSITORY), **kwargs)

    def test_channels_and_non_publishing_pr(self):
        self.assertEqual(self.resolve()["channel"], "main")
        self.assertEqual(self.resolve("schedule")["channel"], "nightly")
        self.assertEqual(self.resolve("workflow_dispatch", {"channel": "nightly"})["channel"], "nightly")
        pr = self.resolve("pull_request", ref="refs/pull/41/merge")
        self.assertEqual(pr["publish"], "false")
        self.assertEqual(pr["commit"], SHA)

    def test_rejects_wrong_repository_ref_event_and_sha(self):
        for kwargs in [{"repository": "Autumn-27/artex"}, {"ref": "refs/heads/feature"},
                       {"ref": "refs/tags/v1.0.0"}, {"sha": "abc"}, {"sha": "1" * 40 + "\n"}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.resolve(**kwargs)
        with self.assertRaises(ValueError):
            self.resolve("pull_request_target")
        with self.assertRaises(ValueError):
            self.resolve("release")

    def test_rejects_injected_channel_or_tag(self):
        for inputs in [{"channel": "main\npublish=true"}, {"channel": "stable", "release_tag": "--help"},
                       {"channel": "stable", "release_tag": "v1.2.3\ncommit=x"},
                       {"channel": "stable", "release_tag": "v1.2.3-rc.1"},
                       {"channel": "main", "release_tag": "v1.2.3"}]:
            with self.subTest(inputs=inputs), self.assertRaises(ValueError):
                self.resolve("workflow_dispatch", inputs)

    def test_stable_requires_published_release_and_main_ancestry(self):
        calls = []
        def git(*args):
            calls.append(args)
            return TAG_SHA if args[0] == "rev-parse" else ""
        release = {"tag_name": "v1.2.3", "draft": False, "prerelease": False,
                   "published_at": "2026-11-26T00:00:00Z"}
        result = self.resolve("workflow_dispatch", {"channel": "stable", "release_tag": "v1.2.3"},
                              release_lookup=lambda _: release, git_command=git)
        self.assertEqual(result["commit"], TAG_SHA)
        self.assertEqual(result["version"], "v1.2.3")
        self.assertIn(("merge-base", "--is-ancestor", TAG_SHA, "refs/remotes/origin/main"), calls)
        for key, value in [("draft", True), ("prerelease", True), ("published_at", None),
                           ("tag_name", "v9.0.0")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.resolve("workflow_dispatch", {"channel": "stable", "release_tag": "v1.2.3"},
                             release_lookup=lambda _: {**release, key: value}, git_command=git)
        def not_ancestor(*args):
            if args[0] == "merge-base":
                raise subprocess.CalledProcessError(1, ["git", *args])
            return TAG_SHA
        with self.assertRaises(subprocess.CalledProcessError):
            self.resolve("workflow_dispatch", {"channel": "stable", "release_tag": "v1.2.3"},
                         release_lookup=lambda _: release, git_command=not_ancestor)


class SchemaFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.write("db/schema.sql", "CREATE TABLE example(id INT)")
        self.write("db/db.go", "package db")
        self.write("traffic/traffic.go", "package traffic")

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def test_database_and_data_format_changes_change_fingerprint(self):
        for name in ["db/schema.sql", "db/db.go", "traffic/traffic.go", "skillprovider/catalog.go",
                     "config/config.go", "server/server.go", "agent/seeder.go",
                     "newpackage/store.go", "root.go"]:
            before = schema_fingerprint(self.root)
            self.write(name, "// migrate persisted format\nCREATE TABLE x(id INT)")
            self.assertNotEqual(before, schema_fingerprint(self.root), name)

    def test_ignores_tests_and_non_migrating_frontend_code(self):
        before = schema_fingerprint(self.root)
        self.write("db/db_test.go", "CREATE TABLE injected(id INT)")
        self.write("db/testdata/foo.go", "ALTER TABLE x ADD bar INT")
        self.write("tools/ui.go", "package tools")
        self.write("web/generated.go", "CREATE TABLE x(id INT)")
        self.assertEqual(before, schema_fingerprint(self.root))

    def test_names_are_part_of_fingerprint(self):
        before = schema_fingerprint(self.root)
        (self.root / "db/db.go").rename(self.root / "db/store.go")
        self.assertNotEqual(before, schema_fingerprint(self.root))

    def test_rejects_symlinks_and_missing_schema(self):
        (self.root / "db/db.go").unlink()
        (self.root / "db/db.go").symlink_to("schema.sql")
        with self.assertRaises(ValueError):
            schema_fingerprint(self.root)
        (self.root / "db/schema.sql").unlink()
        with self.assertRaises(ValueError):
            schema_fingerprint(self.root)


if __name__ == "__main__":
    unittest.main()
