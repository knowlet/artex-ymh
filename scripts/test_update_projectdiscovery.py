"""Offline contract and failure tests for the release metadata updater."""
from __future__ import annotations

import copy
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import update_projectdiscovery as updater


def fixture_release(name, version="v1.2.3"):
    repository = f"projectdiscovery/{name}"
    filenames = [f"{name}_checksums.txt"]
    if name != "nuclei-templates":
        filenames += [f"{name}_1.2.3_linux_{arch}.zip" for arch in ("amd64", "arm64")]
    return {
        "tag_name": version, "draft": False, "prerelease": False,
        "html_url": f"https://github.com/{repository}/releases/tag/{version}",
        "published_at": "2026-10-24T00:00:00Z",
        "assets": [{"name": filename, "digest": "sha256:" + "a" * 64,
                    "browser_download_url": f"https://github.com/{repository}/releases/download/{version}/{filename}"}
                   for filename in filenames],
    }


def fixture_fetch(url):
    parts = url.split("/")
    name = parts[5]
    if url.endswith("/releases/latest"):
        return fixture_release(name)
    if "/commits/" in url:
        return {"sha": "b" * 40}
    if "/contents/LICENSE.md?ref=" in url:
        return {"encoding": "base64", "content": base64.b64encode(
            b'MIT License\nPermission is hereby granted, free of charge\n'
            b'The above copyright notice and this permission notice shall be included\n'
            b'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND'
        ).decode("ascii")}
    raise AssertionError(f"unexpected metadata request: {url}")


class ReleaseLockTests(unittest.TestCase):
    def test_repository_lock_validates_with_real_metadata(self):
        updater.validate_lock(json.loads(updater.DEFAULT_OUTPUT.read_text(encoding="utf-8")))

    def test_refresh_pins_all_repositories_and_archives_without_downloads(self):
        requested = []
        def fetch(url):
            requested.append(url)
            return fixture_fetch(url)
        lock = updater.refresh(fetch)
        updater.validate_lock(lock)
        self.assertEqual(len(requested), 18)
        self.assertEqual([entry["name"] for entry in lock["tools"]], list(updater.TOOLS))
        self.assertTrue(all("api.github.com/repos/projectdiscovery/" in url for url in requested))
        self.assertEqual(len(lock["tools"][-1]["assets"]), 1)
        self.assertIn("checksums file only", lock["tools"][-1]["artifact_note"])

    def test_reject_unverifiable_or_misdirected_assets(self):
        release = fixture_release("httpx")
        mutations = (
            lambda value: value.update(prerelease=True),
            lambda value: value.update(draft=True),
            lambda value: value.update(tag_name="../../main"),
            lambda value: value.update(published_at=None),
            lambda value: value.update(html_url="https://example.org/release"),
            lambda value: value["assets"][1].update(digest=None),
            lambda value: value["assets"][1].update(digest="sha256:" + "g" * 64),
            lambda value: value["assets"][1].update(browser_download_url="http://github.com/archive.zip"),
            lambda value: value["assets"].pop(),
            lambda value: value["assets"].append(copy.deepcopy(value["assets"][1])),
            lambda value: value["assets"].pop(0),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                bad = copy.deepcopy(release)
                mutate(bad)
                with self.assertRaises(updater.UpdateError):
                    updater.release_entry("httpx", bad, {"sha": "b" * 40})
        with self.assertRaises(updater.UpdateError):
            updater.release_entry("httpx", release, {"sha": "main"})

    def test_changed_or_missing_license_requires_review(self):
        for metadata in (
            {}, {"encoding": "base64", "content": "%%%"},
            {"encoding": "base64", "content": base64.b64encode(b"Some other license").decode("ascii")},
        ):
            with self.subTest(metadata=metadata):
                with self.assertRaises(updater.UpdateError):
                    updater.verify_mit_license(metadata, "httpx")

    def test_reject_lock_tampering_and_unknown_entries(self):
        lock = updater.refresh(fixture_fetch)
        for mutate in (
            lambda value: value["tools"].append(None),
            lambda value: value["tools"][0].update(source_url="https://example.org/"),
            lambda value: value["tools"][0].update(license="unknown"),
            lambda value: value["tools"][0]["assets"][0].update(sha256=""),
        ):
            with self.subTest(mutate=mutate):
                bad = copy.deepcopy(lock)
                mutate(bad)
                with self.assertRaises(updater.UpdateError):
                    updater.validate_lock(bad)

    def test_check_never_writes_on_match_drift_or_network_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            updater.atomic_write(path, updater.refresh(fixture_fetch))
            before = path.read_bytes()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(updater.main(["--check", "--output", str(path)], fixture_fetch), 0)
                def changed(url):
                    if url.endswith("/releases/latest"):
                        return fixture_release(url.split("/")[5], "v1.2.4")
                    return fixture_fetch(url)
                self.assertEqual(updater.main(["--check", "--output", str(path)], changed), 1)
                def unavailable(url):
                    raise urllib.error.URLError("offline")
                self.assertEqual(updater.main(["--check", "--output", str(path)], unavailable), 2)
            self.assertEqual(path.read_bytes(), before)

    def test_incomplete_refresh_preserves_existing_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text("previous reviewed lock", encoding="utf-8")
            def unavailable(url):
                if "katana" in url:
                    raise urllib.error.URLError("rate limited")
                return fixture_fetch(url)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(updater.main(["--output", str(path)], unavailable), 2)
            self.assertEqual(path.read_text(encoding="utf-8"), "previous reviewed lock")

    def test_atomic_write_failure_preserves_existing_lock_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text("previous reviewed lock", encoding="utf-8")
            with patch.object(updater.os, "replace", side_effect=OSError("replace failed")):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(updater.main(["--output", str(path)], fixture_fetch), 2)
            self.assertEqual(path.read_text(encoding="utf-8"), "previous reviewed lock")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_output_failure_after_commit_reports_changed_lock(self):
        class ClosedOutput(io.StringIO):
            def __init__(self, fail_during_flush):
                super().__init__()
                self.fail_during_flush = fail_during_flush

            def write(self, value):
                if not self.fail_during_flush:
                    raise BrokenPipeError("output closed")
                return super().write(value)

            def flush(self):
                raise BrokenPipeError("output closed during flush")

        for fail_during_flush in (False, True):
            with self.subTest(fail_during_flush=fail_during_flush):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "lock.json"
                    path.write_text("previous reviewed lock", encoding="utf-8")
                    errors = io.StringIO()
                    with redirect_stdout(ClosedOutput(fail_during_flush)), redirect_stderr(errors):
                        self.assertEqual(updater.main(["--output", str(path)], fixture_fetch), 3)
                    self.assertEqual(json.loads(path.read_text(encoding="utf-8")), updater.refresh(fixture_fetch))
                    self.assertIn(f"release lock committed to {path}", errors.getvalue())
                    self.assertNotIn("unchanged", errors.getvalue())

    def test_closed_output_does_not_change_precommit_failure_result(self):
        class ClosedOutput:
            def write(self, value):
                raise BrokenPipeError("output closed")

            def flush(self):
                raise BrokenPipeError("output closed")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text("previous reviewed lock", encoding="utf-8")
            errors = io.StringIO()
            def unavailable(url):
                raise urllib.error.URLError("offline")
            with redirect_stdout(ClosedOutput()), redirect_stderr(errors):
                self.assertEqual(updater.main(["--output", str(path)], unavailable), 2)
            self.assertEqual(path.read_text(encoding="utf-8"), "previous reviewed lock")
            self.assertIn("release lock unchanged", errors.getvalue())

    def test_process_closed_pipe_preserves_committed_exit_three(self):
        child_code = """
import io, json, runpy, sys
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import test_update_projectdiscovery as fixtures
script = sys.argv[1] + '/update_projectdiscovery.py'
output = sys.argv[2]
class Opener:
    def open(self, request, timeout):
        return io.BytesIO(json.dumps(fixtures.fixture_fetch(request.full_url)).encode())
sys.argv = [script, '--output', output]
with patch('urllib.request.build_opener', return_value=Opener()):
    runpy.run_path(script, run_name='__main__')
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text("previous reviewed lock", encoding="utf-8")
            read_fd, write_fd = os.pipe()
            os.close(read_fd)
            try:
                process = subprocess.Popen(
                    [sys.executable, "-c", child_code, str(updater.ROOT / "scripts"), str(path)],
                    stdout=write_fd, stderr=subprocess.PIPE,
                )
            finally:
                os.close(write_fd)
            _, diagnostic = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 3, diagnostic.decode())
            self.assertIn(b"release lock committed", diagnostic)
            self.assertNotIn(b"Exception ignored", diagnostic)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), updater.refresh(fixture_fetch))

    def test_offline_validation_does_not_fetch(self):
        def unexpected(url):
            raise AssertionError("offline validation must not fetch")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(updater.main(["--validate"], unexpected), 0)

    def test_metadata_response_bounds_and_redirect_policy(self):
        class Response(io.BytesIO):
            pass
        class Opener:
            def open(self, request, timeout):
                self.timeout = timeout
                return Response(b" " * (updater.MAX_RESPONSE + 1))
        opener = Opener()
        with patch.object(updater.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(updater.UpdateError):
                updater.github_json("https://api.github.com/repos/projectdiscovery/httpx/releases/latest")
        self.assertEqual(opener.timeout, 20)
        for url in ("http://api.github.com/repos/x", "https://api.github.com.evil.test/repos/x", "https://example.org/"):
            with self.assertRaises(updater.UpdateError):
                updater.github_json(url)
        with self.assertRaises(updater.UpdateError):
            updater.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.test/")


if __name__ == "__main__":
    unittest.main()
