"""Replay the actual pinned Trivy report, not a guessed native schema.

The byte-for-byte fixture comes from PR #12 run 41599255318, artifact
13213417286, local-scanner-evidence/trivy-vulnerable/native.json.
It scans an authored SBOM, not a remote target. Mutations below are synthetic
negative/compatibility tests and are not represented as new scanner runs.
"""
import copy
import hashlib
from pathlib import Path
import unittest

import worker as w

FIXTURE = Path(__file__).with_name("testdata") / "trivy-0.76.1-go-sbom.json"
NAME = "github.com/gogo/protobuf"
EXPECTED = {(NAME, "1.3.1")}
OTHER = ("example.invalid/artex-fixture", "1.3.1")


class TrivyInventoryContracts(unittest.TestCase):
    def setUp(self):
        self.native = w.document(FIXTURE.read_bytes())

    def parse(self, native=None, expected=None, code=0):
        return w.parse_results("trivy", w.encoded(self.native if native is None else native),
                               code, EXPECTED if expected is None else expected)

    def test_fixture_matches_retained_native_sha256(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
                         "7ab8b1be90eb636b24dcf0cb65bb629e169e0415192d336f8525677b339e1ec3")
        self.assertEqual(self.native["Trivy"]["Version"], "0.76.1")
        self.assertEqual(self.native["Results"][0]["Type"], "gobinary")

    def test_real_go_sbom_report_preserves_finding(self):
        rows = self.parse()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["package"], row["version"]), (NAME, "1.3.1"))
        self.assertEqual(row["advisory_id"], "CVE-2021-3121")
        self.assertEqual(row["aliases"], ["GHSA-c3h9-896r-86jm"])
        self.assertEqual(row["fixed_versions"], ["1.3.2"])
        self.assertEqual(row["severity"], "HIGH")
        self.assertEqual(row["validation"], "database-match; exploitability-unverified")

    def test_gomod_compatibility_and_leading_v(self):
        self.native["Results"][0]["Type"] = "gomod"
        self.native["Results"][0]["Packages"][0]["Version"] = "v1.3.1"
        self.native["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "v1.3.1"
        self.assertEqual(self.parse()[0]["version"], "1.3.1")

    def test_only_go_result_types_are_accepted(self):
        for value in (None, "", "go", "npm", "debian", "gobinary-unknown", {}, []):
            native = copy.deepcopy(self.native)
            native["Results"][0]["Type"] = value
            with self.subTest(value=value), self.assertRaises(w.ScanError):
                self.parse(native)

    def test_no_findings_still_requires_explicit_inventory(self):
        for kind in ("gomod", "gobinary"):
            for value in (None, []):
                native = copy.deepcopy(self.native)
                native["Results"][0].update(Type=kind, Vulnerabilities=value)
                with self.subTest(kind=kind, value=value):
                    self.assertEqual(self.parse(native), [])
            native["Results"][0].pop("Vulnerabilities")
            self.assertEqual(self.parse(native), [])

    def test_malformed_vulnerabilities_are_not_empty_success(self):
        # gomod exercises the pre-existing false-clean path independently of
        # the real fixture's previously unsupported gobinary label.
        for value in ({}, "", False, 0, "invalid", [None], [{}]):
            native = copy.deepcopy(self.native)
            native["Results"][0].update(Type="gomod", Vulnerabilities=value)
            with self.subTest(value=value), self.assertRaises((w.ScanError, KeyError)):
                self.parse(native)

    def test_findings_cannot_substitute_for_package_inventory(self):
        for kind in ("gomod", "gobinary"):
            native = copy.deepcopy(self.native)
            native["Results"][0].update(Type=kind, Packages=[])
            with self.subTest(kind=kind), self.assertRaises(w.ScanError):
                self.parse(native)

    def test_missing_null_or_malformed_inventory_fails(self):
        for value in (None, {}, "", False, [None], [{}]):
            native = copy.deepcopy(self.native)
            native["Results"][0]["Packages"] = value
            with self.subTest(value=value), self.assertRaises((w.ScanError, KeyError)):
                self.parse(native)
        self.native["Results"][0].pop("Packages")
        with self.assertRaises(w.ScanError):
            self.parse()

    def test_missing_input_package_cannot_be_clean(self):
        self.native["Results"][0].pop("Vulnerabilities")
        with self.assertRaisesRegex(w.ScanError, "incomplete scanner coverage"):
            self.parse(expected=EXPECTED | {OTHER})

    def test_mixed_inventory_covers_vulnerable_and_no_advisory_packages(self):
        self.native["Results"][0]["Packages"].append({"Name": OTHER[0], "Version": OTHER[1]})
        self.assertEqual(len(self.parse(expected=EXPECTED | {OTHER})), 1)

    def test_vulnerability_must_belong_to_its_result_inventory(self):
        other_result = {"Type": "gomod", "Packages": [{"Name": OTHER[0], "Version": OTHER[1]}],
                        "Vulnerabilities": self.native["Results"][0].pop("Vulnerabilities")}
        self.native["Results"].append(other_result)
        with self.assertRaisesRegex(w.ScanError, "inventory"):
            self.parse(expected=EXPECTED | {OTHER})

    def test_foreign_package_and_foreign_vulnerability_rejected(self):
        for field, name_key in (("Packages", "Name"), ("Vulnerabilities", "PkgName")):
            native = copy.deepcopy(self.native)
            native["Results"][0][field][0][name_key] = OTHER[0]
            with self.subTest(field=field), self.assertRaises(w.ScanError):
                self.parse(native)

    def test_native_failure_wrong_schema_and_missing_results_rejected(self):
        for code in (1, 2, -9):
            with self.subTest(code=code), self.assertRaises(w.ScanError):
                self.parse(code=code)
        self.native["SchemaVersion"] = 3
        with self.assertRaises(w.ScanError):
            self.parse()
        for results in (None, {}, [None], []):
            with self.subTest(results=results), self.assertRaises(w.ScanError):
                self.parse({"SchemaVersion": 2, "Results": results})

    def test_invalid_fixed_version_and_alias_shapes_rejected(self):
        for key in ("FixedVersion", "VendorIDs"):
            for value in ({}, False, 0):
                native = copy.deepcopy(self.native)
                native["Results"][0]["Vulnerabilities"][0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(w.ScanError):
                    self.parse(native)

    def test_duplicate_findings_and_aliases_are_normalized(self):
        vuln = self.native["Results"][0]["Vulnerabilities"][0]
        vuln["VendorIDs"].append(vuln["VendorIDs"][0])
        self.native["Results"][0]["Vulnerabilities"].append(copy.deepcopy(vuln))
        rows = self.parse()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["aliases"], ["GHSA-c3h9-896r-86jm"])


if __name__ == "__main__":
    unittest.main()
