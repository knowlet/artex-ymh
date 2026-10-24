import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("update_nuclei_index", Path(__file__).with_name("update_nuclei_index.py"))
index = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(index)


def row(template_id="CVE-2026-12345", path=None):
    return {"ID": template_id, "Info": {"Name": "Example component", "Severity": "high",
        "Description": "This descriptive text must not be imported.", "Classification": {"CVSSScore": "8.1"}},
        "file_path": path or "http/cves/2026/" + template_id + ".yaml",
        "http": [{"raw": "REQUEST CONTENT MUST NOT BE IMPORTED"}]}


def raw_rows(*rows):
    return ("\n".join(json.dumps(value) for value in rows) + "\n").encode()


def lock():
    return {"schema_version": 1, "tools": [{"name": "nuclei-templates", "repository": index.REPOSITORY,
        "license": "MIT", "commit": "a" * 40, "version": "v10.5.1", "release_published_at": "2026-10-23T11:19:55Z",
        "release_url": "https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.5.1"}]}


class IndexTests(unittest.TestCase):
    def test_normalization_metadata_only_and_multiple_templates(self):
        raw = raw_rows(row("CVE-2026-12345-b"), row("CVE-2026-12345-a"))
        doc = index.snapshot(raw)
        self.assertEqual((doc["count"], doc["unique_cve_count"]), (2, 1))
        self.assertEqual(doc["templates"][0]["template_id"], "CVE-2026-12345-a")
        self.assertEqual(doc["templates"][0]["cvss_score"], 8.1)
        self.assertEqual(doc["license"], "unverified")
        self.assertEqual(doc["source"], {"kind": "local-unverified", "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertNotIn("Description", index.encoded(doc).decode())
        self.assertNotIn("REQUEST CONTENT", index.encoded(doc).decode())
        self.assertEqual(index.encoded(doc), index.encoded(index.snapshot(raw)))

    def test_official_source_identity_and_raw_blob(self):
        raw = raw_rows(row())
        source = index.lock_source(lock())
        doc = index.snapshot(raw, source)
        self.assertEqual(doc["license"], "MIT")
        self.assertEqual(doc["source"]["blob_sha"], hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
        self.assertEqual(doc["source"]["commit"], "a" * 40)
        self.assertEqual(doc["license_file"], "discovery/NUCLEI-LICENSE.txt")
        for edit in ({"url": "https://evil.invalid/cves.json"}, {"commit": "no"}, {"sha256": "no"}, {"blob_sha": "no"}):
            changed = copy.deepcopy(doc)
            changed["source"].update(edit)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                index.validate_index(changed)

    def test_reject_invalid_json_and_duplicate_keys(self):
        for raw in (b"", b"{", b"[]\n", b'{"ID":"x","ID":"y"}\n', b'{"Info":NaN}\n', b"[" * 3000 + b"0" + b"]" * 3000):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                index.normalize_rows(raw)

    def test_reject_invalid_template_metadata(self):
        cases = []
        for path in ("../x.yaml", "/http/cves/2026/x.yaml", "http/cves/2026/../x.yaml", "http//cves/2026/x.yaml",
                     "http/cves/2026/x.yml?remote", "http\\cves\\2026\\x.yaml", "code/cves/2026/x.yaml", "http/cves/2026/x.txt"):
            value = row(); value["file_path"] = path; cases.append(value)
        for bad_id in ("CVE-2026-1", "CVE-2026-12345,other", "--help", "CVE-2026-12345http"):
            value = row(); value["ID"] = bad_id; cases.append(value)
        for severity in ("bad", [], None):
            value = row(); value["Info"]["Severity"] = severity; cases.append(value)
        for score in ("11", "-1", "nan", 8.1, [], None):
            value = row(); value["Info"]["Classification"]["CVSSScore"] = score; cases.append(value)
        value = row(); value["Info"]["Name"] = "bad\nname"; cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                index.normalize_rows(raw_rows(value))
        with self.assertRaises(ValueError):
            index.normalize_rows(raw_rows(row(), row()))
        value = row(); value["Info"]["Classification"]["CVSSScore"] = "N/A"
        self.assertNotIn("cvss_score", index.snapshot(raw_rows(value))["templates"][0])

    def test_reject_normalized_tampering_and_payload_fields(self):
        doc = index.snapshot(raw_rows(row()))
        for edit in ({"count": 2}, {"unique_cve_count": 2}, {"license": "MIT"}):
            changed = copy.deepcopy(doc); changed.update(edit)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                index.validate_index(changed)
        for edit in ({"cve_id": "CVE-2026-99999"}, {"protocol": "network"}, {"cvss_score": True},
                     {"cvss_score": float("inf")}, {"description": "forbidden"}, {"http": []}):
            changed = copy.deepcopy(doc); changed["templates"][0].update(edit)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                index.validate_index(changed)

    def test_official_fetch_and_notice_failure_preserve_old_file(self):
        raw = raw_rows(row())
        notice = index.DEFAULT_LICENSE.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); output = root / "index.json"; lockfile = root / "lock.json"
            lockfile.write_text(json.dumps(lock())); output.write_text("old")
            def fetch(url, limit=index.MAX_BYTES):
                return notice if url.endswith("LICENSE.md") else raw
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(index.main(["--lock", str(lockfile), "--output", str(output)], fetch=fetch), 0)
            doc = json.loads(output.read_bytes()); self.assertEqual(doc["source"]["kind"], "official-github")
            previous = output.read_bytes()
            def changed_notice(url, limit=index.MAX_BYTES):
                return notice + b"different\n" if url.endswith("LICENSE.md") else raw
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(index.main(["--lock", str(lockfile), "--output", str(output)], fetch=changed_notice), 1)
            self.assertEqual(output.read_bytes(), previous)

    def test_offline_check_and_failed_replace_preserve_old_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / "raw.jsonl"; output = root / "index.json"
            source.write_bytes(raw_rows(row())); output.write_text("{}")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(index.main(["--input", str(source), "--output", str(output), "--check"]), 2)
                self.assertEqual(output.read_text(), "{}")
                self.assertEqual(index.main(["--input", str(source), "--output", str(output)]), 0)
                self.assertEqual(index.main(["--input", str(source), "--output", str(output), "--check"]), 0)
            previous = output.read_bytes()
            with mock.patch.object(index.os, "replace", side_effect=OSError("replace failed")), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(index.main(["--input", str(source), "--output", str(output)]), 1)
            self.assertEqual(output.read_bytes(), previous)
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["index.json", "raw.jsonl"])

    def test_source_hosts_redirects_and_bounds(self):
        for url in ("http://raw.githubusercontent.com/" + index.REPOSITORY + "/" + "a" * 40 + "/cves.json",
                    "https://evil.invalid/source", "https://raw.githubusercontent.com/other/repo/" + "a" * 40 + "/cves.json",
                    index.RAW_BASE + "a" * 40 + "/other", index.RAW_BASE + "a" * 40 + "/cves.json?x=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                index.download(url)
        with self.assertRaises(ValueError):
            index.NoRedirects().redirect_request(None, None, 302, "found", {}, "https://evil.invalid/")
        with mock.patch.object(index, "MAX_BYTES", 1), self.assertRaises(ValueError):
            index.normalize_rows(raw_rows(row()))
        with mock.patch.object(index, "MAX_LINE", 1), self.assertRaises(ValueError):
            index.normalize_rows(raw_rows(row()))

    def test_lock_identity_and_license_validation(self):
        for field, value in (("commit", "bad"), ("repository", "other/repo"), ("license", "other"),
                             ("version", "v10.5.1;bad"), ("release_published_at", "2026-99-99T00:00:00Z")):
            changed = lock(); changed["tools"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                index.lock_source(changed)
        for notice in (b"", b"MIT License only", b"\xff"):
            with self.assertRaises(ValueError):
                index.verify_notice(notice)

    def test_committed_reporting_failure_is_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / "raw.jsonl"; output = root / "index.json"
            source.write_bytes(raw_rows(row()))
            with mock.patch("builtins.print", side_effect=[BrokenPipeError("closed"), None]):
                self.assertEqual(index.main(["--input", str(source), "--output", str(output)]), 3)
            self.assertEqual(json.loads(output.read_bytes())["count"], 1)

    @unittest.skipIf(os.name == "nt", "POSIX closed-pipe subprocess contract")
    def test_real_closed_stdout_preserves_committed_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / "raw.jsonl"; output = root / "index.json"
            source.write_bytes(raw_rows(row()))
            read_fd, write_fd = os.pipe()
            os.close(read_fd)
            with os.fdopen(write_fd, "wb") as closed_pipe:
                result = subprocess.run([sys.executable, str(Path(index.__file__)),
                    "--input", str(source), "--output", str(output)],
                    stdout=closed_pipe, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 3, result.stderr.decode())
            self.assertIn(b"committed", result.stderr)
            document = json.loads(output.read_bytes())
            index.validate_index(document)
            self.assertEqual(document["count"], 1)
            self.assertEqual(document["source"]["kind"], "local-unverified")

    def test_repository_snapshot_validates(self):
        document = json.loads(index.DEFAULT_OUTPUT.read_bytes())
        index.validate_index(document)
        self.assertEqual(index.encoded(document), index.DEFAULT_OUTPUT.read_bytes())
        self.assertEqual(document["source"]["commit"], index.lock_source(json.loads(index.DEFAULT_LOCK.read_bytes()))["commit"])
        self.assertEqual(document["count"], len(document["templates"]))


if __name__ == "__main__":
    unittest.main()
