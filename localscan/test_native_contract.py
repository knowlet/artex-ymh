"""Contracts derived from the pinned scanners' real acceptance failures."""
import copy
import datetime as dt
from unittest import mock
from pathlib import Path
import unittest

import worker as w
from test_worker import OSV, EXPECTED


class NativeContracts(unittest.TestCase):
    def test_osv_scalibr_cache_layout(self):
        self.assertEqual(w.DB_FILES["osv-scanner"], ("osv-scalibr/Go/all.zip",))
        argv = w.sandbox_command(Path("/private/stage"))
        index = argv.index("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")
        self.assertEqual(argv[index + 1], "/db")
        self.assertNotIn("--download-offline-databases", w.tool_args("osv-scanner"))

    def test_osv_plugin_error_with_results_fails_closed(self):
        for code in (0, 1):
            for errors in ([{"name": "osv/osvlocal", "status": {"status": 2}}],
                           {"error": "invalid shape"}, "failed", False):
                value = copy.deepcopy(OSV)
                if code == 0:
                    value["results"][0]["packages"][0]["vulnerabilities"] = []
                value["errors"] = errors
                with self.subTest(code=code, errors=errors), self.assertRaises(w.ScanError):
                    w.parse_results("osv-scanner", w.encoded(value), code, EXPECTED)

    def test_empty_osv_error_list_allows_valid_complete_result(self):
        for errors in (None, []):
            value = copy.deepcopy(OSV)
            value["errors"] = errors
            self.assertTrue(w.parse_results("osv-scanner", w.encoded(value), 1, EXPECTED))

    def test_rfc3339_fractional_precision_and_offsets(self):
        for digits in ("", "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789"):
            text = "2026-11-03T07:00:00" + ("." + digits if digits else "") + "Z"
            expected = int((digits + "000000")[:6])
            self.assertEqual(w.timestamp(text), dt.datetime(2026, 11, 3, 7, 0, 0, expected, tzinfo=dt.timezone.utc))
        self.assertEqual(w.timestamp("2026-11-03T15:00:00.123456789+08:00"),
                         dt.datetime(2026, 11, 3, 7, 0, 0, 123456, tzinfo=dt.timezone.utc))
        original = dt.datetime
        class Python310Contract:
            @staticmethod
            def fromisoformat(text):
                # Ensure the compatibility path is exercised even on a newer
                # test interpreter, instead of inheriting its permissiveness.
                if text != "2026-11-03T07:00:00.123456+00:00":
                    raise AssertionError("fraction was not normalized for Python 3.10")
                return original.fromisoformat(text)
        with mock.patch.object(w.dt, "datetime", Python310Contract):
            self.assertEqual(w.timestamp("2026-11-03T07:00:00.123456789Z").microsecond, 123456)

    def test_invalid_rfc3339_is_rejected(self):
        for text in (None, "2026-11-03", "2026-11-03T00:00:00", "2026-11-03 00:00:00Z",
                     "2026-11-03T00:00:00.1234567890Z", "2026-13-03T00:00:00Z",
                     "2026-11-03T00:00:00+00:60", "2026-11-03T00:00:00+24:00"):
            with self.subTest(text=text), self.assertRaises(w.ScanError):
                w.timestamp(text)


if __name__ == "__main__":
    unittest.main()
