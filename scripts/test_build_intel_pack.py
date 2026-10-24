"""Offline behavior and failure tests for the manifest builder."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import build_intel_pack as builder
import test_update_projectdiscovery as releases_fixtures
import test_update_vulnerability_intel as kev_fixtures


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.kev = builder.kev.snapshot(kev_fixtures.raw(kev_fixtures.fixture()), "a" * 40)
        self.lock = builder.releases.refresh(releases_fixtures.fixture_fetch)
        self.index = {"schema_version": 1, "source": {
            "kind": "official-github", "repository": "projectdiscovery/nuclei-templates",
            "commit": "b" * 40, "blob_sha": "c" * 40, "sha256": "d" * 64,
            "url": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/" + "b" * 40 + "/cves.json",
            "release": "v1.2.3", "release_published_at": "2026-10-24T00:00:00Z"},
            "license": "MIT", "license_file": "discovery/NUCLEI-LICENSE.txt",
            "count": 1, "unique_cve_count": 1, "templates": [{
                "cve_id": "CVE-2026-12345", "template_id": "CVE-2026-12345",
                "title": "Synthetic fixture", "severity": "medium", "cvss_score": 5.0,
                "path": "http/cves/2026/CVE-2026-12345.yaml", "protocol": "http"}]}
        self.write_inputs()

    def write_inputs(self):
        (self.root / builder.KEV_NAME).write_bytes(builder.kev.encoded(self.kev))
        (self.root / builder.RELEASE_NAME).write_bytes(builder.kev.encoded(self.lock))
        (self.root / builder.NUCLEI_NAME).write_bytes(builder.kev.encoded(self.index))
        (self.root / "discovery").mkdir(exist_ok=True)
        (self.root / "discovery/NUCLEI-LICENSE.txt").write_bytes(
            b'MIT License\nPermission is hereby granted, free of charge\n'
            b'The above copyright notice and this permission notice shall be included\n'
            b'THE SOFTWARE IS PROVIDED "AS IS"\n')

    def invoke(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return builder.main(["--packaging-dir", str(self.root), *args])

    def test_deterministic_exact_bytes_manifest(self):
        document = builder.build(self.root)
        self.assertEqual(document, builder.build(self.root))
        self.assertEqual([item["name"] for item in document["files"]], ["cisa-kev", "projectdiscovery-releases", "nuclei-cve-index"])
        self.assertEqual(document["files"][0]["source_date"], self.kev["dateReleased"])
        self.assertEqual(document["files"][1]["source_date"], "2026-10-24T00:00:00Z")
        for entry in document["files"]:
            raw = (self.root / entry["path"]).read_bytes()
            self.assertEqual(entry["bytes"], len(raw))
            self.assertEqual(entry["sha256"], hashlib.sha256(raw).hexdigest())
        original_inputs = [(self.root / name).read_bytes() for name in (builder.KEV_NAME, builder.RELEASE_NAME, builder.NUCLEI_NAME)]
        self.assertEqual(self.invoke(), 0)
        output = self.root / "discovery-data-manifest.json"
        before = output.read_bytes()
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(original_inputs, [(self.root / name).read_bytes() for name in (builder.KEV_NAME, builder.RELEASE_NAME, builder.NUCLEI_NAME)])

    def test_check_drift_and_missing_never_write(self):
        output = self.root / "discovery-data-manifest.json"
        self.assertEqual(self.invoke("--check"), 1)
        self.assertFalse(output.exists())
        self.assertEqual(self.invoke(), 0)
        before = output.read_bytes()
        self.assertEqual(self.invoke("--check"), 0)
        with (self.root / builder.KEV_NAME).open("ab") as stream:
            stream.write(b"\n")
        self.assertEqual(self.invoke("--check"), 1)
        self.assertEqual(output.read_bytes(), before)

    def test_reject_local_or_forged_provenance(self):
        mutations = (
            lambda value: value.update(schema_version=2),
            lambda value: value.update(license="unverified"),
            lambda value: value.update(scope="All CVEs"),
            lambda value: value["source"].update(kind="local-unverified"),
            lambda value: value["source"].update(commit="main"),
            lambda value: value["source"].update(sha256="not-a-hash"),
            lambda value: value["source"].update(repository="other/repo"),
            lambda value: value["source"].update(url="https://example.invalid/data"),
            lambda value: value.update(license_url="https://example.invalid/license"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                bad = copy.deepcopy(self.kev)
                mutate(bad)
                with self.assertRaises(ValueError):
                    builder.official_kev(builder.kev.encoded(bad))

    def test_bad_input_keeps_manifest(self):
        self.assertEqual(self.invoke(), 0)
        output = self.root / "discovery-data-manifest.json"
        before = output.read_bytes()
        for raw in (b"{", b'{"count":1,"count":2}', b"[]", b"", b"\xff"):
            with self.subTest(raw=raw):
                (self.root / builder.KEV_NAME).write_bytes(raw)
                self.assertEqual(self.invoke(), 2)
                self.assertEqual(output.read_bytes(), before)
        self.write_inputs()
        self.lock["tools"][0]["assets"][0]["sha256"] = "invalid"
        self.write_inputs()
        self.assertEqual(self.invoke(), 2)
        self.assertEqual(output.read_bytes(), before)

    def test_count_duplicate_cve_and_invalid_dates_rejected(self):
        for mutate in (
            lambda value: value.update(count=2),
            lambda value: value.update(vulnerabilities=value["vulnerabilities"] * 2, count=2),
            lambda value: value.update(dateReleased="bad"),
        ):
            bad = copy.deepcopy(self.kev)
            mutate(bad)
            with self.assertRaises(ValueError):
                builder.official_kev(builder.kev.encoded(bad))
        self.lock["tools"][0]["release_published_at"] = "2026-99-24T00:00:00Z"
        self.write_inputs()
        with self.assertRaises(ValueError):
            builder.build(self.root)

    def test_metadata_index_corruption_and_release_mismatch_preserves_manifest(self):
        self.assertEqual(self.invoke(), 0)
        output = self.root / "discovery-data-manifest.json"
        before = output.read_bytes()
        for mutate in (
            lambda value: value.update(count=2),
            lambda value: value.update(unique_cve_count=0),
            lambda value: value["source"].update(commit="c" * 40,
                url="https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/" + "c" * 40 + "/cves.json"),
            lambda value: value["source"].update(release="v1.2.4"),
            lambda value: value["source"].update(release_published_at="2026-10-25T00:00:00Z"),
            lambda value: value["templates"][0].update(path="../../outside.yaml"),
        ):
            with self.subTest(mutate=mutate):
                bad = copy.deepcopy(self.index)
                mutate(bad)
                (self.root / builder.NUCLEI_NAME).write_bytes(builder.kev.encoded(bad))
                self.assertEqual(self.invoke(), 2)
                self.assertEqual(output.read_bytes(), before)

    def test_missing_or_escaping_license_notice_preserves_manifest(self):
        self.assertEqual(self.invoke(), 0)
        output = self.root / "discovery-data-manifest.json"
        before = output.read_bytes()
        notice = self.root / "discovery/NUCLEI-LICENSE.txt"
        notice.unlink()
        self.assertEqual(self.invoke(), 2)
        notice.write_bytes(b"unlicensed content")
        self.assertEqual(self.invoke(), 2)
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside) / "LICENSE.txt"
            external.write_bytes(b"MIT License")
            notice.unlink()
            notice.symlink_to(external)
            self.assertEqual(self.invoke(), 2)
        self.assertEqual(output.read_bytes(), before)

    def test_missing_special_and_oversized_source(self):
        path = self.root / builder.KEV_NAME
        path.unlink()
        self.assertEqual(self.invoke(), 2)
        path.mkdir()
        self.assertEqual(self.invoke(), 2)
        path.rmdir()
        path.write_bytes(b" " * 10)
        with self.assertRaises(ValueError):
            builder.read_source(self.root, builder.KEV_NAME, 4)
        if hasattr(os, "mkfifo"):
            path.unlink()
            os.mkfifo(path)
            self.assertEqual(self.invoke(), 2)

    def test_source_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside) / "source.json"
            external.write_bytes((self.root / builder.KEV_NAME).read_bytes())
            source = self.root / builder.KEV_NAME
            source.unlink()
            source.symlink_to(external)
            self.assertEqual(self.invoke(), 2)

    def test_destination_cannot_overwrite_inputs_or_escape(self):
        for output in (self.root / builder.KEV_NAME, self.root / builder.RELEASE_NAME, self.root / builder.NUCLEI_NAME, self.root.parent / "outside.json"):
            with self.subTest(output=output):
                self.assertEqual(self.invoke("--output", str(output)), 2)
        linked = self.root / "manifest.json"
        linked.symlink_to(self.root / builder.KEV_NAME)
        self.assertEqual(self.invoke("--output", str(linked)), 2)

    def test_failed_replace_preserves_manifest_and_cleans_temp(self):
        self.assertEqual(self.invoke(), 0)
        output = self.root / "discovery-data-manifest.json"
        before = output.read_bytes()
        entries = set(self.root.iterdir())
        with mock.patch.object(builder.kev.os, "replace", side_effect=OSError("simulated replace failure")):
            self.assertEqual(self.invoke(), 2)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(set(self.root.iterdir()), entries)

    def test_failed_success_report_returns_committed_exit(self):
        class BrokenOutput(io.StringIO):
            def write(self, value):
                raise BrokenPipeError("closed stdout")
        output = self.root / "discovery-data-manifest.json"
        self.assertEqual(self.invoke(), 0)
        before = output.read_bytes()
        with (self.root / builder.KEV_NAME).open("ab") as stream:
            stream.write(b"\n")
        errors = io.StringIO()
        with redirect_stdout(BrokenOutput()), redirect_stderr(errors):
            code = builder.main(["--packaging-dir", str(self.root)])
        self.assertEqual(code, 3)
        self.assertNotEqual(output.read_bytes(), before)
        self.assertIn("committed", errors.getvalue())
        self.assertNotIn("unchanged", errors.getvalue())
        self.assertEqual(json.loads(output.read_bytes()), builder.build(self.root))

    def test_failed_check_report_does_not_claim_commit(self):
        class BrokenOutput(io.StringIO):
            def write(self, value):
                raise BrokenPipeError("closed stdout")
        self.assertEqual(self.invoke(), 0)
        output = self.root / "discovery-data-manifest.json"
        before = output.read_bytes()
        errors = io.StringIO()
        with redirect_stdout(BrokenOutput()), redirect_stderr(errors):
            code = builder.main(["--packaging-dir", str(self.root), "--check"])
        self.assertEqual(code, 2)
        self.assertEqual(output.read_bytes(), before)
        self.assertNotIn("committed", errors.getvalue())

    def test_real_closed_stdout_preserves_committed_exit(self):
        self.assertEqual(self.invoke(), 0)
        output = self.root / "discovery-data-manifest.json"
        before = output.read_bytes()
        with (self.root / builder.KEV_NAME).open("ab") as stream:
            stream.write(b"\n")
        process = subprocess.Popen(
            [sys.executable, str(Path(builder.__file__).resolve()),
             "--packaging-dir", str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL)
        process.stdout.close()
        try:
            code = process.wait(timeout=10)
            errors = process.stderr.read().decode("utf-8")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stderr.close()
        self.assertEqual(code, 3, errors)
        self.assertIn("committed", errors)
        self.assertNotEqual(output.read_bytes(), before)
        self.assertEqual(json.loads(output.read_bytes()), builder.build(self.root))

    def test_repository_inputs_build_and_validate(self):
        document = builder.build(builder.ROOT / "packaging")
        self.assertEqual(document["files"][0]["license"], "CC0-1.0")
        self.assertEqual(document["files"][1]["license"], "MIT")


if __name__ == "__main__":
    unittest.main()
