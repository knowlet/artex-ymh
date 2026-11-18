import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("sync_antifox", Path(__file__).with_name("sync_antifox.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ROOT = Path(__file__).resolve().parents[1]


class AntiFoxBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        shutil.copytree(ROOT / "providers/antifox", self.root / "providers/antifox")

    def test_actual_bundle_is_current(self):
        self.assertEqual(MODULE.sync(ROOT), 86)

    def test_generate_check_and_idempotence(self):
        with self.assertRaisesRegex(ValueError, "missing generated"):
            MODULE.sync(self.root)
        self.assertEqual(MODULE.sync(self.root, write=True), 86)
        first = MODULE.generated_files(self.root)
        self.assertEqual(MODULE.sync(self.root, write=True), 86)
        self.assertEqual(MODULE.generated_files(self.root), first)

    def test_source_tamper_publishes_nothing(self):
        source = self.root / "providers/antifox/snapshot/skills/ssrf-testing/SKILL.md"
        source.write_bytes(source.read_bytes() + b"\nchanged\n")
        with self.assertRaisesRegex(ValueError, "source identity mismatch"):
            MODULE.sync(self.root, write=True)
        self.assertFalse((self.root / "skills").exists())

    def test_resource_tamper_publishes_nothing(self):
        source = self.root / "providers/antifox/snapshot/skills/report-generation/prompts/report-level.tmpl"
        source.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "source identity mismatch"):
            MODULE.sync(self.root, write=True)
        self.assertFalse((self.root / "skills").exists())

    def test_existing_operator_edit_is_preserved(self):
        MODULE.sync(self.root, write=True)
        output = self.root / "skills/antifox-ssrf-testing/SKILL.md"
        output.write_text("operator edit")
        with self.assertRaisesRegex(ValueError, "refusing to overwrite existing edits"):
            MODULE.sync(self.root, write=True)
        self.assertEqual(output.read_text(), "operator edit")

    def test_output_symlink_is_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "skills").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink output refused"):
            MODULE.sync(self.root, write=True)
        self.assertEqual(list(outside.iterdir()), [])

    def test_catalog_report_import_boundary(self):
        catalog = json.loads((self.root / "providers/antifox/catalog.json").read_text())
        report = next(s for s in catalog["skills"] if s["id"] == "report-generation")
        self.assertEqual(report["import_policy"], "metadata-only")
        self.assertIn("antifox-report-engine", report["dependencies"])


if __name__ == "__main__":
    unittest.main()
