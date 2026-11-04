import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

import worker as w

spec = importlib.util.spec_from_file_location('installer', Path(__file__).resolve().parents[1] / 'scripts/install_local_scanners.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

NAME = 'github.com/gogo/protobuf'
EXPECTED = {(NAME, '1.3.1')}
BOM = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
       'components': [{'type': 'library', 'name': NAME, 'version': '1.3.1', 'purl': 'pkg:golang/' + NAME + '@1.3.1'}]}
OSV = {'results': [{'source': {'type': 'sbom', 'path': '/input/bom.json'}, 'packages': [
    {'package': {'name': NAME, 'version': '1.3.1', 'ecosystem': 'Go'}, 'vulnerabilities': [
        {'id': 'GHSA-c3h9-896r-86jm', 'aliases': ['CVE-2021-3121'], 'affected': [
            {'package': {'name': NAME, 'ecosystem': 'Go'}, 'ranges': [{'events': [{'fixed': '1.3.2'}]}]}]}]}]}]}
TRIVY = {'SchemaVersion': 2, 'Results': [{'Type': 'gomod', 'Packages': [{'Name': NAME, 'Version': 'v1.3.1'}],
          'Vulnerabilities': [{'VulnerabilityID': 'CVE-2021-3121', 'PkgName': NAME, 'InstalledVersion': 'v1.3.1',
                              'FixedVersion': '1.3.2', 'Severity': 'HIGH'}]}]}


class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def bom(self, value=None):
        path = self.root / 'bom.json'
        path.write_bytes(w.encoded(BOM if value is None else value))
        return path

    def db(self, tool='osv-scanner'):
        root = self.root / tool
        root.mkdir()
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        for name in w.DB_FILES[tool]:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(w.encoded({'Version': 2, 'UpdatedAt': now}) if name.endswith('.json') else b'fixture-database')
        receipt = w.db_receipt(tool, root, 'unit-test fixture, not a real vulnerability DB', now)
        (root / 'artex-db.json').write_bytes(w.encoded(receipt))
        return root, receipt

    def test_canonical_input_removes_external_references(self):
        bom = copy.deepcopy(BOM)
        bom['externalReferences'] = [{'url': 'https://unauthorized.invalid'}]
        bom['components'][0]['externalReferences'] = bom['externalReferences']
        _, staged, covered = w.input_sbom(self.bom(bom))
        self.assertNotIn(b'unauthorized', staged)
        self.assertEqual(covered, EXPECTED)

    def test_empty_unsupported_and_nested_inputs_rejected(self):
        variants = []
        for change in [{'components': []}, {'bomFormat': 'SPDX'}, {'specVersion': '9.0'}]:
            variants.append({**BOM, **change})
        for field, value in [('type', 'application'), ('purl', 'pkg:npm/example@1.0.0'),
                             ('components', [{}]), ('name', 'other'), ('version', '2.0.0'),
                             ('purl', 'pkg:golang/x/../y@1.2.3'), ('purl', 'pkg:golang/x@1.2.3?url=https://bad.invalid')]:
            bom = copy.deepcopy(BOM)
            bom['components'][0][field] = value
            variants.append(bom)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(w.ScanError):
                w.input_sbom(self.bom(value))

    def test_duplicate_package_rejected(self):
        bom = copy.deepcopy(BOM)
        bom['components'].append(bom['components'][0])
        with self.assertRaises(w.ScanError):
            w.input_sbom(self.bom(bom))

    def test_duplicate_json_key_nonfinite_and_invalid_json(self):
        for value in [b'{"a":1,"a":2}', b'{"a":NaN}', b'{', b'\xff']:
            with self.subTest(value=value), self.assertRaises(w.ScanError):
                w.document(value)

    def test_symlink_and_oversized_input(self):
        source = self.bom()
        link = self.root / 'link'
        link.symlink_to(source)
        with self.assertRaises(OSError):
            w.read_file(link, 10000)
        with self.assertRaises(w.ScanError):
            w.read_file(source, 1)

    def test_osv_findings_and_fixed_version(self):
        rows = w.parse_results('osv-scanner', w.encoded(OSV), 1, EXPECTED)
        self.assertEqual(rows[0]['fixed_versions'], ['1.3.2'])
        self.assertEqual(rows[0]['aliases'], ['CVE-2021-3121'])

    def test_trivy_findings_and_go_version_normalization(self):
        rows = w.parse_results('trivy', w.encoded(TRIVY), 0, EXPECTED)
        self.assertEqual(rows[0]['version'], '1.3.1')
        self.assertEqual(rows[0]['severity'], 'HIGH')

    def test_no_findings_requires_inventory(self):
        osv = copy.deepcopy(OSV)
        osv['results'][0]['packages'][0]['vulnerabilities'] = []
        trivy = copy.deepcopy(TRIVY)
        trivy['Results'][0]['Vulnerabilities'] = None
        for tool, native in [('osv-scanner', osv), ('trivy', trivy)]:
            self.assertEqual(w.parse_results(tool, w.encoded(native), 0, EXPECTED), [])

    def test_exit_failure_is_not_clean(self):
        for tool, native, code in [('osv-scanner', OSV, 0), ('osv-scanner', OSV, 2), ('trivy', TRIVY, 1)]:
            with self.subTest(tool=tool, code=code), self.assertRaises(w.ScanError):
                w.parse_results(tool, w.encoded(native), code, EXPECTED)

    def test_empty_partial_unknown_schema_fail_closed(self):
        cases = [('osv-scanner', {'results': []}, 0), ('trivy', {'SchemaVersion': 2, 'Results': []}, 0),
                 ('osv-scanner', {}, 0), ('trivy', {**TRIVY, 'SchemaVersion': 3}, 0)]
        for tool, native, code in cases:
            with self.subTest(tool=tool, native=native), self.assertRaises(w.ScanError):
                w.parse_results(tool, w.encoded(native), code, EXPECTED)
        with self.assertRaises(w.ScanError):
            w.parse_results('trivy', w.encoded(TRIVY), 0, EXPECTED | {('example.org/missing', '1.0.0')})

    def test_out_of_input_package_rejected(self):
        with self.assertRaises(w.ScanError):
            w.parse_results('trivy', w.encoded(TRIVY), 0, {('example.org/other', '1.0.0')})

    def test_db_snapshot_integrity(self):
        root, receipt = self.db()
        target = self.root / 'snapshot'
        result = w.copy_db('osv-scanner', root, target, dt.datetime.now(dt.timezone.utc))
        self.assertEqual(result['files'], receipt['files'])
        self.assertEqual((target / w.DB_FILES['osv-scanner'][0]).read_bytes(), b'fixture-database')

    def test_db_missing_corrupt_and_extra_manifest_file(self):
        root, receipt = self.db()
        db = root / w.DB_FILES['osv-scanner'][0]
        db.write_bytes(b'corrupt')
        with self.assertRaises(w.ScanError):
            w.copy_db('osv-scanner', root, self.root / 'snapshot', dt.datetime.now(dt.timezone.utc))
        db.unlink()
        with self.assertRaises(OSError):
            w.copy_db('osv-scanner', root, self.root / 'snapshot', dt.datetime.now(dt.timezone.utc))
        receipt['files']['../escape'] = {'sha256': 'a' * 64, 'size': 1}
        (root / 'artex-db.json').write_bytes(w.encoded(receipt))
        with self.assertRaises(w.ScanError):
            w.copy_db('osv-scanner', root, self.root / 'snapshot', dt.datetime.now(dt.timezone.utc))

    def test_stale_future_timezone_missing_rejected(self):
        now = dt.datetime.now(dt.timezone.utc)
        for value in [(now - dt.timedelta(days=8)).isoformat(), (now + dt.timedelta(hours=1)).isoformat(),
                      '2026-01-01T00:00:00', None]:
            with self.subTest(value=value), self.assertRaises(w.ScanError):
                w.fresh(value, now)

    def test_trivy_database_metadata_checked(self):
        root, _ = self.db('trivy')
        w.copy_db('trivy', root, self.root / 'snapshot', dt.datetime.now(dt.timezone.utc))
        metadata = root / 'db/metadata.json'
        metadata.write_bytes(w.encoded({'Version': 99, 'UpdatedAt': dt.datetime.now(dt.timezone.utc).isoformat()}))
        receipt = w.db_receipt('trivy', root, 'fixture', dt.datetime.now(dt.timezone.utc).isoformat())
        (root / 'artex-db.json').write_bytes(w.encoded(receipt))
        with self.assertRaises(w.ScanError):
            w.copy_db('trivy', root, self.root / 'snapshot2', dt.datetime.now(dt.timezone.utc))

    def test_db_symlink_refused(self):
        root, _ = self.db()
        target = root / w.DB_FILES['osv-scanner'][0]
        target.unlink()
        target.symlink_to(self.bom())
        with self.assertRaises(w.ScanError):
            w.copy_db('osv-scanner', root, self.root / 'snapshot', dt.datetime.now(dt.timezone.utc))

    def test_static_elf_validation(self):
        data = bytearray(120)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, 62)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<I', data, 64, 1)
        w.static_elf(data)
        struct.pack_into('<I', data, 64, 3)
        with self.assertRaises(w.ScanError):
            w.static_elf(data)
        with self.assertRaises(w.ScanError):
            w.static_elf(b'not executable')

    def test_no_online_or_active_scanner_flags(self):
        self.assertIn('--offline', w.tool_args('osv-scanner'))
        self.assertNotIn('--offline-vulnerabilities', w.tool_args('osv-scanner'))
        self.assertIn('--skip-db-update', w.tool_args('trivy'))
        for tool in ('ffuf', 'zap', 'php2shell', 'sh'):
            with self.assertRaises(w.ScanError):
                w.tool_args(tool)

    def test_namespace_and_environment_contract(self):
        argv = w.sandbox_command(self.root)
        for required in ('--unshare-all', '--die-with-parent', '--clearenv', '--ro-bind', '--cap-drop'):
            self.assertIn(required, argv)
        self.assertNotIn('--share-net', argv)
        self.assertNotIn('/var/run/docker.sock', argv)
        self.assertNotIn('HTTP_PROXY', argv)
        self.assertNotIn('GITHUB_TOKEN', argv)

    def test_bounded_real_subprocess(self):
        code, out, err, failure = w.bounded_process([sys.executable, '-c', 'print("ok")'], 3)
        self.assertEqual((code, out, err, failure), (0, b'ok\n', b'', None))

    def test_timeout_kills_subprocess(self):
        code, _, _, failure = w.bounded_process([sys.executable, '-c', 'import time; time.sleep(5)'], 0.05)
        self.assertNotEqual(code, 0)
        self.assertIsInstance(failure, w.ScanError)

    def test_output_limit_is_error(self):
        with mock.patch.object(w, 'MAX_OUTPUT', 100):
            code, out, _, failure = w.bounded_process([sys.executable, '-c', 'print("x"*10000)'], 3)
        self.assertIsInstance(failure, w.ScanError)
        self.assertLessEqual(len(out), 100)

    def test_child_credentials_are_not_inherited(self):
        with mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'test-not-a-secret', 'TRIVY_CONFIG': 'wrong'}):
            _, out, _, error = w.bounded_process([sys.executable, '-c', 'import os; print(os.getenv("GITHUB_TOKEN"), os.getenv("TRIVY_CONFIG"))'], 3)
        self.assertIsNone(error)
        self.assertEqual(out, b'None None\n')

    def test_atomic_result_replacement(self):
        path = self.root / 'result.json'
        w.atomic_json(path, {'status': 'running', 'complete': False})
        w.atomic_json(path, {'status': 'failed', 'complete': False})
        self.assertEqual(w.document(path.read_bytes())['status'], 'failed')

    def test_install_is_separate_and_no_overwrite(self):
        destination = self.root / 'managed'
        files = {'osv-scanner': (b'fixture, never executed', 0o755), 'licenses/osv-scanner/LICENSE': (b'notice', 0o644)}
        installer.install_files(files, destination)
        self.assertEqual((destination / 'osv-scanner').read_bytes(), files['osv-scanner'][0])
        with self.assertRaises(ValueError):
            installer.install_files(files, destination)
        self.assertEqual((destination / 'osv-scanner').stat().st_mode & 0o777, 0o755)

    def test_install_bad_path_never_published(self):
        destination = self.root / 'managed'
        with self.assertRaises(ValueError):
            installer.install_files({'../escape': (b'bad', 0o644)}, destination)
        self.assertFalse(destination.exists())

    def test_source_registry_version_drift_refused(self):
        lock = w.document(w.LOCK_PATH.read_bytes())
        registry = {'projects': [{'repository': s['repository'], 'ref': s['version'], 'commit': s['commit'], 'license': s['license']}
                                 for s in lock['bundled'].values()]}
        installer.check_registry(lock, registry)
        registry['projects'][0]['ref'] = 'v999.0.0'
        with self.assertRaises(ValueError):
            installer.check_registry(lock, registry)

    def test_no_shell_or_arbitrary_arguments_in_plan(self):
        for tool in w.TOOLS:
            argv = w.tool_args(tool)
            self.assertNotIn('-c', argv)
            self.assertNotIn('fix', argv)
            self.assertNotIn('image', argv)
            self.assertEqual(argv[-1], '/input/bom.json')


if __name__ == '__main__':
    unittest.main()
