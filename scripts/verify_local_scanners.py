#!/usr/bin/env python3
"""Opt-in real-binary CI acceptance, using only authored local SBOM fixtures.

Online phase: official pinned releases and vulnerability DB preparation only.
Scan phase: the managed no-network namespace, never remote targets. Requires
an already-built ARTEX binary as argv[1] and an absent evidence dir as argv[2].
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'localscan'))
import worker as w


def main():
    artex = str(Path(sys.argv[1]).resolve())
    evidence = Path(sys.argv[2]).resolve()
    evidence.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix='artex-acceptance-') as temporary:
        root = Path(temporary)
        cache, install = root / 'sources', root / 'managed'
        env = {'PATH': os.environ['PATH'], 'HOME': str(root), 'LANG': 'C.UTF-8'}

        def command(argv, expected=0, filename=None, timeout=600):
            run = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=root, timeout=timeout)
            if filename:
                (evidence / (filename + '.stdout')).write_bytes(run.stdout)
                (evidence / (filename + '.stderr')).write_bytes(run.stderr)
            if run.returncode != expected:
                raise RuntimeError(f'{argv[:3]}: expected {expected}, got {run.returncode}: {run.stderr[-3000:]!r} {run.stdout[-3000:]!r}')
            return run.stdout

        installer = [sys.executable, str(ROOT / 'scripts/install_local_scanners.py'), '--cache', str(cache)]
        command(installer + ['--download', '--bundle', str(root / 'one.tar.gz'), '--install-dir', str(install)], filename='install')
        command(installer + ['--bundle', str(root / 'two.tar.gz')], filename='offline-rebuild')
        first = hashlib.sha256((root / 'one.tar.gz').read_bytes()).hexdigest()
        second = hashlib.sha256((root / 'two.tar.gz').read_bytes()).hexdigest()
        assert first == second, 'bundle is not reproducible'
        (evidence / 'bundle-sha256.json').write_bytes(w.encoded({'first': first, 'second': second}))
        (evidence / 'tools-manifest.json').write_bytes((install / 'tools-manifest.json').read_bytes())
        (evidence / 'sources.lock.json').write_bytes((install / 'sources.lock.json').read_bytes())
        command(installer + ['--install-dir', str(install)], expected=2, filename='refuse-overwrite')
        for tool in w.TOOLS:
            version = command([str(install / tool), '--version'], filename=tool + '-version').decode()
            assert ('2.7.0' if tool == 'osv-scanner' else '0.76.1') in version
            command([str(install / tool), *(['scan', 'source'] if tool == 'osv-scanner' else ['sbom']), '--help'], filename=tool + '-help')

        # The only live downloads after install are explicitly separated DB prep.
        osv_db = root / 'osv-db'
        target = osv_db / 'osv-scanner/Go/all.zip'
        target.parent.mkdir(parents=True)
        url = 'https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip'
        with urllib.request.urlopen(url, timeout=120) as response, target.open('xb') as output:
            total = 0
            while True:
                block = response.read(min(w.DB_CHUNK, w.MAX_DB - total + 1))
                if not block:
                    break
                total += len(block)
                if total > w.MAX_DB:
                    raise RuntimeError('OSV DB download exceeds byte budget')
                output.write(block)
        assert total > 0, 'empty OSV database download'
        trivy_db = root / 'trivy-db'
        trivy_db.mkdir()
        command([str(install / 'trivy'), 'image', '--download-db-only', '--cache-dir', str(trivy_db), '--skip-version-check', '--disable-telemetry', '--no-progress'],
                filename='trivy-db-preparation')
        sizes = {tool: {name: (db / name).stat().st_size for name in w.DB_FILES[tool]}
                 for tool, db in [('osv-scanner', osv_db), ('trivy', trivy_db)]}
        (evidence / 'database-sizes.json').write_bytes(w.encoded(sizes))
        print('Prepared DB byte sizes: ' + json.dumps(sizes), flush=True)
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        for tool, db, source in [('osv-scanner', osv_db, url), ('trivy', trivy_db, 'official Trivy DB OCI repositories; see preparation stderr')]:
            command([artex, 'scan', 'seal-db', '--tool', tool, '--db-dir', str(db), '--source', source, '--retrieved-at', now], filename=tool + '-seal')
            (evidence / (tool + '-db.json')).write_bytes((db / 'artex-db.json').read_bytes())

        bom = root / 'bom.json'
        for tool, db in [('osv-scanner', osv_db), ('trivy', trivy_db)]:
            for label, name, expected in [('vulnerable', 'github.com/gogo/protobuf', 1),
                                           ('no-advisory-fixture', 'example.invalid/artex-fixture', 0)]:
                bom.write_bytes(w.encoded({'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                    'components': [{'type': 'library', 'name': name, 'version': '1.3.1', 'purl': f'pkg:golang/{name}@1.3.1'}]}))
                base = ['--tool', tool, '--install-dir', str(install), '--sbom', str(bom), '--db-dir', str(db)]
                command([artex, 'scan', 'plan', *base], filename=f'{tool}-{label}-plan')
                result = json.loads(command([artex, 'scan', 'run', *base, '--authorized', '--timeout', '300',
                                            '--report-dir', str(evidence / f'{tool}-{label}')], expected=expected, filename=f'{tool}-{label}-run', timeout=360))
                assert result['complete'] is True
                assert result['status'] == ('findings' if expected else 'no_findings')
                if expected:
                    ids = {v for row in result['findings'] for v in [row['advisory_id'], *row['aliases']]}
                    assert 'CVE-2021-3121' in ids or 'GHSA-c3h9-896r-86jm' in ids
                command([artex, 'scan', 'run', *base, '--report-dir', str(evidence / f'{tool}-denied')], expected=2,
                        filename=f'{tool}-{label}-authorization-denied')
                assert not (evidence / f'{tool}-denied').exists()
            receipt_path = db / 'artex-db.json'
            original = receipt_path.read_bytes()
            receipt = json.loads(original)
            receipt['files'][w.DB_FILES[tool][0]]['sha256'] = '0' * 64
            receipt_path.write_bytes(w.encoded(receipt))
            command([artex, 'scan', 'plan', *base], expected=2, filename=tool + '-corrupt-db')
            receipt_path.unlink()
            command([artex, 'scan', 'plan', *base], expected=2, filename=tool + '-missing-db')
            receipt_path.write_bytes(original)
        (evidence / 'acceptance.json').write_bytes(w.encoded({'complete': True, 'targets': 'authored local Go SBOM fixtures only',
             'checks': ['source/hash/license verification', 'two byte-identical bundle builds', 'offline source-cache rebuild',
                        'fresh isolated installation', 'real binary versions/help', 'real DB preparation separate from scan',
                        'both scanners finding known advisory in no-network sandbox', 'both scanners no-advisory fixture',
                        'explicit authorization required', 'corrupt and missing DB refused'],
             'not_tested': ['production deployment', 'filesystem/image scans', 'other ecosystems', 'signature attestations']}))
        print('Real local-scanner acceptance passed; evidence: ' + str(evidence))


if __name__ == '__main__':
    main()
