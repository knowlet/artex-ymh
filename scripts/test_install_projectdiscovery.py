"""Offline adversarial archive and replacement tests; no upstream binaries run."""

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

SPEC = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install_projectdiscovery.py"))
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


MIT_NOTICE = b"Copyright (c) fixture\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software.\nTHE SOFTWARE IS PROVIDED AS IS.\n"


def archive(entries=None, include_license=True):
    result = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(result, "w") as bundle:
            entries = entries or [("httpx", b"fixture executable, never run")]
            if include_license and not any((name.filename if isinstance(name, zipfile.ZipInfo) else name) in installer.LICENSE_NAMES for name, _ in entries):
                entries = [("LICENSE.md", MIT_NOTICE)] + entries
            for name, content in entries:
                bundle.writestr(name, content)
    return result.getvalue()


def lock_for(data):
    name = "httpx_1.12.0_linux_amd64.zip"
    return {"schema_version": 1, "tools": [{
        "name": "httpx", "repository": "projectdiscovery/httpx", "version": "v1.12.0",
        "commit": "a" * 40, "assets": [{"name": name,
            "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/" + name,
            "sha256": hashlib.sha256(data).hexdigest()}]}]}


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name) / "data"
        (self.data_dir / "tools").mkdir(parents=True)
        self.destination = self.data_dir / "tools/httpx"
        self.destination.write_bytes(b"original")

    def assert_preserved(self, data, lock=None):
        with self.assertRaises((installer.InstallError, OSError, KeyboardInterrupt)):
            installer.install(lock or lock_for(data), "httpx", self.data_dir, data)
        self.assertEqual(self.destination.read_bytes(), b"original")
        self.assertEqual(list(self.destination.parent.glob(".httpx-*")), [])

    def test_install_exact_binary_and_receipt(self):
        data = archive([("LICENSE.md", MIT_NOTICE), ("httpx", b"fixture executable")])
        receipt = installer.install(lock_for(data), "httpx", self.data_dir, data)
        self.assertEqual(self.destination.read_bytes(), b"fixture executable")
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o755)
        self.assertEqual(receipt["installed_binary_sha256"], hashlib.sha256(b"fixture executable").hexdigest())
        self.assertNotEqual(receipt["archive_sha256"], receipt["installed_binary_sha256"])
        self.assertFalse(receipt["runtime_version_verified"])
        self.assertFalse(receipt["scan_executed"])
        notice = Path(receipt["license_path"])
        self.assertEqual(notice.read_bytes(), MIT_NOTICE)
        self.assertEqual(receipt["license_sha256"], hashlib.sha256(MIT_NOTICE).hexdigest())
        self.assertEqual(list(self.destination.parent.glob(".httpx-*")), [])

    def test_digest_mismatch_preserves_old_file(self):
        data = archive()
        self.assert_preserved(data + b"tamper", lock_for(data))

    def test_traversal_absolute_backslash_duplicate_and_missing(self):
        cases = [
            [("../outside", "bad"), ("httpx", "new")],
            [("/outside", "bad"), ("httpx", "new")],
            [("dir\\outside", "bad"), ("httpx", "new")],
            [("httpx", "new"), ("httpx", "other")],
            [("subdir/httpx", "new")],
            [("httpx", "")],
        ]
        for entries in cases:
            with self.subTest(entries=entries):
                self.assert_preserved(archive(entries))

    def test_symlink_and_fifo_archive_entries(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO):
            with self.subTest(kind=kind):
                entry = zipfile.ZipInfo("httpx")
                entry.create_system = 3
                entry.external_attr = (kind | 0o755) << 16
                self.assert_preserved(archive([(entry, "new")]))

    def test_malformed_archive_preserves_old_file(self):
        self.assert_preserved(b"not a zip")

    def test_limits_preserve_old_file(self):
        data = archive()
        with mock.patch.object(installer, "MAX_ARCHIVE_BYTES", 1):
            self.assert_preserved(data)
        with mock.patch.object(installer, "MAX_BINARY_BYTES", 1):
            self.assert_preserved(data)
        with mock.patch.object(installer, "MAX_TOTAL_BYTES", 1):
            self.assert_preserved(data)

    def test_failed_replace_and_cancel_clean_staging(self):
        data = archive()
        for failure in (OSError("fixture replace failure"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(installer.os, "replace", side_effect=failure):
                    self.assert_preserved(data)

    def test_failed_sync_preserves_old_file(self):
        data = archive()
        with mock.patch.object(installer.os, "fsync", side_effect=OSError("fixture sync failure")):
            self.assert_preserved(data)

    def test_license_write_failure_preserves_old_file(self):
        data = archive()
        with mock.patch.object(installer.os, "link", side_effect=OSError("fixture notice publish failure")):
            self.assert_preserved(data)
        self.assertEqual(list((self.data_dir / "tools/licenses/httpx").glob(".license-*")), [])

    def test_verified_notice_remains_if_binary_replace_fails(self):
        data = archive()
        with mock.patch.object(installer.os, "replace", side_effect=OSError("fixture binary replacement failure")):
            self.assert_preserved(data)
        notices = list((self.data_dir / "tools/licenses/httpx").glob("*.LICENSE.txt"))
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0].read_bytes(), MIT_NOTICE)

    def test_missing_empty_ambiguous_or_invalid_license_preserves_old_file(self):
        cases = [
            archive(include_license=False),
            archive([("LICENSE.md", b""), ("httpx", b"new")]),
            archive([("LICENSE.md", MIT_NOTICE), ("LICENSE", MIT_NOTICE), ("httpx", b"new")]),
            archive([("LICENSE.md", b"not an MIT notice"), ("httpx", b"new")]),
        ]
        for data in cases:
            with self.subTest(size=len(data)):
                self.assert_preserved(data)

    def test_notice_collision_preserves_old_file(self):
        data = archive()
        notice = self.data_dir / "tools/licenses/httpx" / f"{hashlib.sha256(data).hexdigest()}.LICENSE.txt"
        notice.parent.mkdir(parents=True)
        notice.write_bytes(b"operator content")
        self.assert_preserved(data)
        self.assertEqual(notice.read_bytes(), b"operator content")

    def test_reinstall_preserves_same_license_notice(self):
        data = archive()
        first = installer.install(lock_for(data), "httpx", self.data_dir, data)
        second = installer.install(lock_for(data), "httpx", self.data_dir, data)
        self.assertEqual(first["license_path"], second["license_path"])
        self.assertEqual(Path(first["license_path"]).read_bytes(), MIT_NOTICE)

    def test_destination_symlink_rejected(self):
        self.destination.unlink()
        target = Path(self.tmp.name) / "other"
        target.write_bytes(b"original")
        self.destination.symlink_to(target)
        self.assert_preserved(archive())
        self.assertTrue(self.destination.is_symlink())

    def test_lock_rejects_nonofficial_url_missing_digest_duplicate_and_version(self):
        data = archive()
        baseline = lock_for(data)
        variants = []
        altered = copy.deepcopy(baseline)
        altered["tools"][0]["assets"][0]["url"] = "https://attacker.example/httpx.zip"
        variants.append(altered)
        altered = copy.deepcopy(baseline)
        altered["tools"][0]["assets"][0]["sha256"] = ""
        variants.append(altered)
        altered = copy.deepcopy(baseline)
        altered["tools"] *= 2
        variants.append(altered)
        altered = copy.deepcopy(baseline)
        altered["tools"][0]["assets"] *= 2
        variants.append(altered)
        altered = copy.deepcopy(baseline)
        altered["tools"][0]["version"] = "latest"
        variants.append(altered)
        for lock in variants:
            with self.subTest(lock=lock):
                self.assert_preserved(data, lock)

    def test_redirect_host_policy(self):
        for url in ["https://release-assets.githubusercontent.com/file?token=fixture", "https://github.com/file"]:
            installer.validate_download_url(url)
        for url in ["http://github.com/file", "https://evil.example/file", "https://user:pass@github.com/file", "https://github.com:444/file", "https://github.com.evil.example/file"]:
            with self.subTest(url=url), self.assertRaises(installer.InstallError):
                installer.validate_download_url(url)

    def test_offline_cli_installs_without_downloading(self):
        data = archive()
        bundle = Path(self.tmp.name) / "fixture.zip"
        lock = Path(self.tmp.name) / "lock.json"
        bundle.write_bytes(data)
        lock.write_text(json.dumps(lock_for(data)))
        output = io.StringIO()
        with mock.patch.object(installer, "download", side_effect=AssertionError("network not permitted")), mock.patch.object(installer.sys, "stdout", output):
            code = installer.main(["--tool", "httpx", "--lock", str(lock), "--archive", str(bundle), "--data-dir", str(self.data_dir)])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())["installed"])

    def test_cli_download_failure_preserves_old_file(self):
        data = archive()
        lock = Path(self.tmp.name) / "lock.json"
        lock.write_text(json.dumps(lock_for(data)))
        with mock.patch.object(installer, "download", side_effect=OSError("fixture offline")), mock.patch.object(installer.sys, "stderr", io.StringIO()):
            code = installer.main(["--tool", "httpx", "--lock", str(lock), "--data-dir", str(self.data_dir)])
        self.assertEqual(code, 1)
        self.assertEqual(self.destination.read_bytes(), b"original")

    def test_receipt_failure_explicitly_reports_committed_binary(self):
        data = archive()
        bundle = Path(self.tmp.name) / "fixture.zip"
        lock = Path(self.tmp.name) / "lock.json"
        bundle.write_bytes(data)
        lock.write_text(json.dumps(lock_for(data)))
        output = mock.Mock()
        output.write.side_effect = BrokenPipeError("fixture closed stdout")
        errors = io.StringIO()
        with mock.patch.object(installer.sys, "stdout", output), mock.patch.object(installer.sys, "stderr", errors):
            code = installer.main(["--tool", "httpx", "--lock", str(lock), "--archive", str(bundle), "--data-dir", str(self.data_dir)])
        self.assertEqual(code, 3)
        self.assertIn("binary installed", errors.getvalue())
        self.assertEqual(self.destination.read_bytes(), b"fixture executable, never run")
        output.close.assert_not_called()
        self.assertFalse(errors.closed)

    def test_receipt_and_diagnostic_failure_preserves_committed_exit_code(self):
        data = archive()
        bundle = Path(self.tmp.name) / "fixture.zip"
        lock = Path(self.tmp.name) / "lock.json"
        bundle.write_bytes(data)
        lock.write_text(json.dumps(lock_for(data)))
        output, errors = mock.Mock(), mock.Mock()
        output.write.side_effect = BrokenPipeError("fixture closed stdout")
        errors.write.side_effect = BrokenPipeError("fixture closed stderr")
        with mock.patch.object(installer.sys, "stdout", output), mock.patch.object(installer.sys, "stderr", errors):
            code = installer.main(["--tool", "httpx", "--lock", str(lock), "--archive", str(bundle), "--data-dir", str(self.data_dir)])
        self.assertEqual(code, 3)
        output.close.assert_not_called()
        errors.close.assert_not_called()
        self.assertEqual(self.destination.read_bytes(), b"fixture executable, never run")

    def test_actual_closed_os_pipe_exits_three_with_binary_and_license(self):
        data = archive()
        bundle = Path(self.tmp.name) / "fixture.zip"
        lock = Path(self.tmp.name) / "lock.json"
        bundle.write_bytes(data)
        lock.write_text(json.dumps(lock_for(data)))
        command = [sys.executable, str(Path(__file__).with_name("install_projectdiscovery.py")), "--tool", "httpx", "--lock", str(lock), "--archive", str(bundle), "--data-dir", str(self.data_dir)]
        for close_stderr in (False, True):
            with self.subTest(close_stderr=close_stderr):
                # Close the reader before spawning, so the OS guarantees EPIPE
                # even if the child executes faster than the parent can act.
                out_read, out_write = os.pipe()
                os.close(out_read)
                err_write = None
                if close_stderr:
                    err_read, err_write = os.pipe()
                    os.close(err_read)
                try:
                    child = subprocess.Popen(command, stdout=out_write, stderr=err_write if close_stderr else subprocess.PIPE)
                finally:
                    os.close(out_write)
                    if err_write is not None:
                        os.close(err_write)
                _, diagnostic = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 3)
                if not close_stderr:
                    self.assertIn(b"binary installed", diagnostic)
                    self.assertNotIn(b"Exception ignored", diagnostic)
                self.assertEqual(self.destination.read_bytes(), b"fixture executable, never run")
                notices = list((self.data_dir / "tools/licenses/httpx").glob("*.LICENSE.txt"))
                self.assertEqual(len(notices), 1)
                self.assertEqual(notices[0].read_bytes(), MIT_NOTICE)


if __name__ == "__main__":
    unittest.main()
