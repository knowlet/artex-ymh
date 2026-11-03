"""Contracts derived from the pinned scanners' real acceptance failures."""
import copy
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


if __name__ == "__main__":
    unittest.main()
