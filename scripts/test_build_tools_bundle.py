"""Offline tests: no upstream downloads, tool execution, or deployment access."""
import contextlib
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_tools_bundle as b


def tar_bytes(members):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = '../../outside'
            archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
    return out.getvalue()


def zip_bytes(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as archive:
        for name, data in members:
            archive.writestr(name, data)
    return out.getvalue()


def fixture():
    payload = b'#!/bin/sh\nexit 0\n'
    license_text = b'Fixture license\n'
    inputs = {'https://github.com/example/tool/releases/download/v1/tool': payload,
              'https://raw.githubusercontent.com/example/tool/v1/LICENSE': license_text}
    outputs = [('tool', '0755', 'script'), ('licenses/tool/LICENSE', '0644', 'text')]
    downloads = [{'url': u, 'format': 'raw', 'sha256': b.sha256(data),
                  'files': [{'path': path, 'member': '', 'mode': mode, 'check': check}]}
                 for (u, data), (path, mode, check) in zip(inputs.items(), outputs)]
    lock = {'schema': 1, 'platform': 'linux/amd64', 'downloads': downloads,
            'bundled': {'tool': {'version': 'v1', 'upstream': 'https://github.com/example/tool/tree/v1',
                                'license_files': ['licenses/tool/LICENSE']}},
            'external': {'python-tool': {'reason': 'Local virtualenv required', 'upstream': 'https://github.com/example/python'}}}
    manifest = {'tools': [{'name': 'tool', 'path': 'tools/tool', 'sha256': '0' * 64, 'version': 'old'},
                          {'name': 'python-tool', 'path': 'tools/python-tool', 'sha256': '1' * 64}]}
    return lock, manifest, inputs


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.lock, self.manifest, self.inputs = fixture()

    def build(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return b.build_files(self.lock, self.manifest, b'Fixture instructions', self.inputs.__getitem__)

    def test_valid_lock(self):
        b.validate_lock(self.lock, self.manifest)

    def test_actual_repository_lock(self):
        lock = json.loads((b.ROOT / 'packaging/tools-sources.lock.json').read_text())
        manifest = json.loads((b.ROOT / 'packaging/tools-manifest.json').read_text())
        b.validate_lock(lock, manifest)
        self.assertEqual(len(lock['bundled']), 14)
        self.assertEqual(set(lock['external']), {'impacket', 'pypykatz', 'nxc'})
        self.assertTrue(all('/latest/' not in x['url'] for x in lock['downloads']))

    def test_missing_coverage(self):
        del self.lock['external']['python-tool']
        with self.assertRaises(b.BundleError):
            b.validate_lock(self.lock, self.manifest)

    def test_missing_license(self):
        self.lock['bundled']['tool']['license_files'] = ['nonexistent']
        with self.assertRaises(b.BundleError):
            b.validate_lock(self.lock, self.manifest)

    def test_unpinned_input(self):
        del self.lock['downloads'][0]['sha256']
        with self.assertRaises(b.BundleError):
            b.validate_lock(self.lock, self.manifest)

    def test_legacy_member_pin(self):
        spec = self.lock['downloads'][0]
        digest = spec.pop('sha256')
        spec['files'][0]['sha256'] = digest
        b.validate_lock(self.lock, self.manifest)
        self.build()

    def test_duplicate_destination(self):
        self.lock['downloads'][1]['files'][0]['path'] = 'tool'
        with self.assertRaises(b.BundleError):
            b.validate_lock(self.lock, self.manifest)

    def test_reserved_destination(self):
        self.lock['downloads'][0]['files'][0]['path'] = 'SHA256SUMS'
        with self.assertRaises(b.BundleError):
            b.validate_lock(self.lock, self.manifest)

    def test_bad_paths(self):
        for path in ('../x', '/tmp/x', 'x/../../y', 'x\\y', 'C:/x', 'x//y', './x', 'x\ny', ''):
            with self.subTest(path=path), self.assertRaises(b.BundleError):
                b.safe_path(path)

    def test_unapproved_urls(self):
        for url in ('http://github.com/x', 'file:///etc/passwd', 'https://evil.invalid/x',
                    'https://github.com.evil.invalid/x', 'https://user:pass@github.com/x', 'https://github.com:80/x'):
            with self.subTest(url=url), self.assertRaises(b.BundleError):
                b.checked_url(url)

    def test_bad_digest(self):
        self.inputs[next(iter(self.inputs))] = b'changed'
        with self.assertRaises(b.BundleError):
            self.build()

    def test_git_blob_identity(self):
        data = b'hello\n'
        git_hash = hashlib.sha1(b'blob 6\0' + data).hexdigest()
        b.check_hash(data, {'git_blob_sha1': git_hash})
        with self.assertRaises(b.BundleError):
            b.check_hash(data, {'git_blob_sha1': hashlib.sha1(data).hexdigest()})

    def test_checksum_list_is_pinned(self):
        data = (b.sha256(b'file') + '  asset.tar.gz\n').encode()
        spec = {'checksums': {'url': 'https://github.com/x/sums', 'sha256': b.sha256(data), 'filename': 'asset.tar.gz'}}
        self.assertEqual(b.checksum_pin(spec, lambda _: data), b.sha256(b'file'))
        with self.assertRaises(b.BundleError):
            b.checksum_pin(spec, lambda _: data + b'tampered')

    def test_ambiguous_checksum(self):
        data = ((b.sha256(b'file') + '  asset\n') * 2).encode()
        spec = {'checksums': {'url': 'https://github.com/x/sums', 'sha256': b.sha256(data), 'filename': 'asset'}}
        with self.assertRaises(b.BundleError):
            b.checksum_pin(spec, lambda _: data)

    def test_raw_and_gzip(self):
        for kind, data in [('raw', b'abc'), ('gz', gzip.compress(b'abc'))]:
            self.assertEqual(b.extract_selected(data, kind, {''}), {'': b'abc'})

    def test_zip_and_tar(self):
        archives = [('zip', zip_bytes([('binary', b'abc')])),
                    ('tar.gz', tar_bytes([('binary', b'abc', tarfile.REGTYPE)]))]
        for kind, data in archives:
            self.assertEqual(b.extract_selected(data, kind, {'binary'}), {'binary': b'abc'})
            with self.assertRaises(b.BundleError):
                b.extract_selected(data, kind, {'missing'})

    def test_path_traversal_in_unselected_member(self):
        archives = [('zip', zip_bytes([('binary', b'ok'), ('../bad', b'bad')])),
                    ('tar.gz', tar_bytes([('binary', b'ok', tarfile.REGTYPE), ('../bad', b'bad', tarfile.REGTYPE)]))]
        for kind, data in archives:
            with self.subTest(kind=kind), self.assertRaises(b.BundleError):
                b.extract_selected(data, kind, {'binary'})

    def test_tar_links_and_devices_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            data = tar_bytes([('binary', b'ok', tarfile.REGTYPE), ('bad', b'', kind)])
            with self.subTest(kind=kind), self.assertRaises(b.BundleError):
                b.extract_selected(data, 'tar.gz', {'binary'})

    def test_zip_symlink_rejected(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            info = zipfile.ZipInfo('link')
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, '../../outside')
        with self.assertRaises(b.BundleError):
            b.extract_selected(out.getvalue(), 'zip', {'link'})

    def test_duplicate_members(self):
        data = tar_bytes([('binary', b'one', tarfile.REGTYPE), ('binary', b'two', tarfile.REGTYPE)])
        with self.assertRaises(b.BundleError):
            b.extract_selected(data, 'tar.gz', {'binary'})

    def test_size_limits(self):
        with self.assertRaises(b.BundleError):
            b.read_limited(io.BytesIO(b'12345'), limit=4)
        with patch.object(b, 'LIMIT', 2), self.assertRaises(b.BundleError):
            b.extract_selected(zip_bytes([('binary', b'abc')]), 'zip', {'binary'})

    def test_member_count_limit(self):
        with patch.object(b, 'MAX_MEMBERS', 1), self.assertRaises(b.BundleError):
            b.extract_selected(zip_bytes([('a', b'a'), ('b', b'b')]), 'zip', {'a'})

    def test_runtime_manifest_updated_without_changing_source(self):
        before = copy.deepcopy(self.manifest)
        files = self.build()
        actual = json.loads(files['tools-manifest.json'][0])
        self.assertEqual(actual['tools'][0]['sha256'], b.sha256(files['tool'][0]))
        self.assertEqual(actual['tools'][0]['version'], 'v1')
        self.assertEqual(actual['tools'][1]['sha256'], '')
        self.assertEqual(before, self.manifest)
        self.assertNotIn('python-tool', files)

    def test_deterministic_archive_and_modes(self):
        files = self.build()
        with tempfile.TemporaryDirectory() as temp:
            a, c = Path(temp) / 'a.tar.gz', Path(temp) / 'different-name.tar.gz'
            b.write_archive(files, a)
            b.write_archive(dict(reversed(list(files.items()))), c)
            self.assertEqual(a.read_bytes(), c.read_bytes())
            b.verify_archive(a)
            with tarfile.open(a, 'r:gz') as archive:
                for info in archive:
                    self.assertTrue(info.name.startswith('data/tools/'))
                    self.assertEqual((info.uid, info.gid, info.mtime), (0, 0, 0))
                    self.assertEqual(info.mode, 0o755 if info.name.endswith('/tool') else 0o644)

    def test_tampering_rejected(self):
        files = self.build()
        files['tool'] = (b'#!/bin/sh\nexit 1\n', 0o755)
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'tools.tar.gz'
            b.write_archive(files, out)
            with self.assertRaises(b.BundleError):
                b.verify_archive(out)

    def test_wrong_mode_rejected(self):
        files = self.build()
        files['tool'] = (files['tool'][0], 0o644)
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'tools.tar.gz'
            b.write_archive(files, out)
            with self.assertRaises(b.BundleError):
                b.verify_archive(out)

    def test_binary_headers(self):
        elf = bytearray(64)
        elf[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', elf, 18, 62)
        b.check_format(elf, 'elf-amd64')
        struct.pack_into('<H', elf, 18, 183)
        with self.assertRaises(b.BundleError):
            b.check_format(elf, 'elf-amd64')
        pe = bytearray(128)
        pe[:2] = b'MZ'
        struct.pack_into('<I', pe, 60, 64)
        pe[64:68] = b'PE\0\0'
        b.check_format(pe, 'pe')
        with self.assertRaises(b.BundleError):
            b.check_format(b'<html>error</html>', 'pe')

    def test_invalid_lock_version_or_platform(self):
        for field, value in [('schema', 99), ('platform', 'linux/arm64')]:
            lock = {**self.lock, field: value}
            with self.assertRaises(b.BundleError):
                b.validate_lock(lock, self.manifest)


if __name__ == '__main__':
    unittest.main()
