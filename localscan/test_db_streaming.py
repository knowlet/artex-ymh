"""Streaming DB regressions discovered by the real Trivy installation gate."""
import datetime as dt
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import worker as w
import test_worker as fixtures


class StreamingContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def db(self, tool='osv-scanner'):
        return fixtures.Contracts.db(self, tool)

    def bom(self):
        return fixtures.Contracts.bom(self)

    def test_database_streaming_exact_limit_and_fixed_blocks(self):
        source, target = self.root / 'large.db', self.root / 'snapshot.db'
        data = bytes(range(256)) * 32
        source.write_bytes(data)
        calls = []
        original = os.fdopen

        class Guard:
            def __init__(self, fd, mode):
                self.file = original(fd, mode)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.file.close()
            def fileno(self):
                return self.file.fileno()
            def read(self, size):
                calls.append(size)
                if not 0 < size <= 97:
                    raise AssertionError('unbounded database read')
                return self.file.read(size)

        with mock.patch.object(w, 'DB_CHUNK', 97), mock.patch.object(w.os, 'fdopen', Guard):
            actual = w.stream_database(source, len(data), target)
        self.assertEqual(actual, {'size': len(data), 'sha256': w.digest(data)})
        self.assertEqual(target.read_bytes(), data)
        self.assertGreater(len(calls), 2)

    def test_database_oversize_empty_and_existing_destination(self):
        source, target = self.root / 'db', self.root / 'copy'
        source.write_bytes(b'abcd')
        with self.assertRaises(w.ScanError):
            w.stream_database(source, 3, target)
        self.assertFalse(target.exists())
        source.write_bytes(b'')
        with self.assertRaises(w.ScanError):
            w.stream_database(source, 3, target)
        self.assertFalse(target.exists())
        source.write_bytes(b'ok')
        target.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):
            w.stream_database(source, 2, target)
        self.assertEqual(target.read_bytes(), b'preserve')

    def test_database_streaming_does_not_use_whole_file_reader(self):
        root, _ = self.db()
        with mock.patch.object(w, 'read_file', side_effect=AssertionError('whole DB read')):
            receipt = w.db_receipt('osv-scanner', root, 'fixture', dt.datetime.now(dt.timezone.utc).isoformat())
        self.assertEqual(receipt['files'][w.DB_FILES['osv-scanner'][0]]['size'], len(b'fixture-database'))

    def test_database_changed_size_removes_partial_copy(self):
        source, target = self.root / 'db', self.root / 'copy'
        source.write_bytes(b'abcdefgh')
        actual = source.stat()
        changed = mock.Mock(st_size=actual.st_size - 1, st_mtime_ns=actual.st_mtime_ns)
        with mock.patch.object(w.os, 'fstat', side_effect=[actual, changed]), self.assertRaises(w.ScanError):
            w.stream_database(source, 8, target)
        self.assertFalse(target.exists())

    def test_database_stream_symlink_and_fifo_rejected(self):
        source = self.root / 'db'
        source.symlink_to(self.bom())
        with self.assertRaises(OSError):
            w.stream_database(source, 1000)
        source.unlink()
        os.mkfifo(source)
        with self.assertRaises(w.ScanError):
            w.stream_database(source, 1000)

    def test_database_total_budget_and_failed_snapshot_cleanup(self):
        root, receipt = self.db('trivy')
        size = sum(item['size'] for item in receipt['files'].values())
        with mock.patch.object(w, 'MAX_DB', size - 1):
            with self.assertRaises(w.ScanError):
                w.db_receipt('trivy', root, 'fixture', dt.datetime.now(dt.timezone.utc).isoformat())
            with self.assertRaises(w.ScanError):
                w.copy_db('trivy', root, self.root / 'snapshot', dt.datetime.now(dt.timezone.utc))
        self.assertFalse((self.root / 'snapshot/db/trivy.db').exists())
        self.assertFalse((self.root / 'snapshot/db/metadata.json').exists())
        receipt['files']['db/metadata.json']['sha256'] = '0' * 64
        (root / 'artex-db.json').write_bytes(w.encoded(receipt))
        with self.assertRaises(w.ScanError):
            w.copy_db('trivy', root, self.root / 'snapshot2', dt.datetime.now(dt.timezone.utc))
        self.assertFalse((self.root / 'snapshot2/db/trivy.db').exists())
        self.assertFalse((self.root / 'snapshot2/db/metadata.json').exists())

    def test_database_metadata_has_separate_small_limit(self):
        root, _ = self.db('trivy')
        with mock.patch.object(w, 'MAX_DB_METADATA', 5), self.assertRaises(w.ScanError):
            w.db_receipt('trivy', root, 'fixture', dt.datetime.now(dt.timezone.utc).isoformat())

    def test_authorization_rejected_before_expensive_preflight(self):
        options = mock.Mock(action='run', authorized=False, timeout=120)
        with mock.patch.object(w, 'verified_binary', side_effect=AssertionError('must not read tool/DB')), self.assertRaises(w.ScanError):
            w.execute(options)


if __name__ == "__main__":
    unittest.main()
