"""Offline distribution contracts; no compiler download, Docker build or scan."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DATA_FILES = (
    "packaging/discovery-data-manifest.json",
    "packaging/vulnerability-intel.json",
    "packaging/projectdiscovery-lock.json",
    "packaging/nuclei-cve-index.json",
    "packaging/tools-manifest.json",
)
MAINTENANCE_FILES = (
    "scripts/update_projectdiscovery.py",
    "scripts/install_projectdiscovery.py",
    "scripts/update_vulnerability_intel.py",
    "scripts/update_nuclei_index.py",
    "scripts/build_intel_pack.py",
)


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="artex-distribution-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def fixture(self) -> Path:
        root = self.directory / "source"
        root.mkdir()
        shutil.copy2(ROOT / "build.sh", root / "build.sh")
        inputs = (*DATA_FILES, *MAINTENANCE_FILES,
                  "packaging/discovery/README.md", "packaging/discovery/RESEARCH.md",
                  "packaging/discovery/VALIDATION.md",
                  "packaging/discovery/NUCLEI-LICENSE.txt",
                  "skills/projectdiscovery-recon/SKILL.md",
                  "skills/vulnerability-triage/SKILL.md",
                  "config.example.json", "start.sh", "start.bat", "README.md",
                  "README-FORK.md", "LICENSE", "server/webui/dist/index.html")
        for name in inputs:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture:" + name + "\n", encoding="utf-8")
        return root

    def fake_go(self) -> Path:
        directory = self.directory / "fake-bin"
        directory.mkdir()
        compiler = directory / "go"
        compiler.write_text("""#!/bin/sh
set -eu
[ "$1" = build ] || exit 82
shift
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then
    shift
    output="$1"
  fi
  shift
done
[ -n "$output" ] || exit 83
printf 'stub-compiled-binary\\n' > "$output"
chmod +x "$output"
""", encoding="utf-8")
        compiler.chmod(0o700)
        return directory

    @unittest.skipUnless(shutil.which("bash") and shutil.which("zip"), "bash and zip required")
    def test_release_zip_contains_offline_resources_and_skills(self):
        root = self.fixture()
        compiler = self.fake_go()
        for goos in ("linux", "windows"):
            with self.subTest(goos=goos):
                env = dict(os.environ, PATH=str(compiler) + os.pathsep + os.environ.get("PATH", ""),
                           ARTEX_BUILD_VERSION="0.0.0", ARTEX_SKIP_FRONTEND="1",
                           ARTEX_COMPRESS="0", ARTEX_PACKAGE="1",
                           ARTEX_TARGET_OS=goos, ARTEX_TARGET_ARCH="amd64")
                result = subprocess.run(["bash", "build.sh", "--target", goos + "/amd64"],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                prefix = f"artex-0.0.0-{goos}-amd64/"
                with zipfile.ZipFile(root / "dist" / (prefix[:-1] + ".zip")) as archive:
                    expected = (*DATA_FILES, *MAINTENANCE_FILES,
                                "packaging/discovery/README.md",
                                "packaging/discovery/NUCLEI-LICENSE.txt",
                                "skills/projectdiscovery-recon/SKILL.md",
                                "skills/vulnerability-triage/SKILL.md", "LICENSE", "README-FORK.md")
                    for name in expected:
                        self.assertEqual(archive.read(prefix + name), (root / name).read_bytes())
                    binary = "artex.exe" if goos == "windows" else "artex"
                    self.assertEqual(archive.read(prefix + binary), b"stub-compiled-binary\n")
                    names = archive.namelist()
                    self.assertFalse(any(name.startswith(prefix + "data/") for name in names))
                    self.assertFalse(any(name.endswith("tools.tar.gz") for name in names))

    @unittest.skipUnless(shutil.which("bash") and shutil.which("zip"), "bash and zip required")
    def test_missing_data_pack_fails_package_instead_of_silent_omission(self):
        root = self.fixture()
        (root / DATA_FILES[0]).unlink()
        compiler = self.fake_go()
        env = dict(os.environ, PATH=str(compiler) + os.pathsep + os.environ.get("PATH", ""),
                   ARTEX_BUILD_VERSION="0.0.0", ARTEX_SKIP_FRONTEND="1", ARTEX_COMPRESS="0",
                   ARTEX_PACKAGE="1", ARTEX_TARGET_OS="linux", ARTEX_TARGET_ARCH="amd64")
        result = subprocess.run(["bash", "build.sh", "--target", "linux/amd64"],
                                cwd=root, env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "dist/artex-0.0.0-linux-amd64.zip").exists())

    def test_both_docker_contexts_stage_same_reviewed_data_without_download(self):
        # Exercise the new plain COPY declarations against real repository
        # inputs. This checks context availability and resulting paths, not
        # Docker/BuildKit execution or network-dependent image layers.
        for dockerfile in ("Dockerfile", "Dockerfile.source"):
            with self.subTest(dockerfile=dockerfile):
                destination = self.directory / dockerfile
                destination.mkdir()
                copied = []
                for line in (ROOT / dockerfile).read_text(encoding="utf-8").splitlines():
                    if not line.startswith("COPY ") or "--from=" in line:
                        continue
                    parts = shlex.split(line)
                    sources, target = parts[1:-1], parts[-1]
                    if not target.startswith(("/app/packaging/", "/app/scripts/")):
                        continue
                    self.assertTrue(target.endswith("/"))
                    output = destination / target.lstrip("/")
                    output.mkdir(parents=True, exist_ok=True)
                    for name in sources:
                        source = ROOT / name
                        self.assertTrue(source.exists(), "missing Docker context input: " + name)
                        if source.is_dir():
                            shutil.copytree(source, output, dirs_exist_ok=True)
                        else:
                            shutil.copy2(source, output / source.name)
                            copied.append(name)
                for name in (*DATA_FILES, *MAINTENANCE_FILES):
                    self.assertIn(name, copied)
                    staged = destination / "app" / name
                    self.assertEqual(staged.read_bytes(), (ROOT / name).read_bytes())
                self.assertTrue((destination / "app/packaging/discovery/README.md").is_file())
                self.assertEqual((destination / "app/packaging/discovery/NUCLEI-LICENSE.txt").read_bytes(),
                                 (ROOT / "packaging/discovery/NUCLEI-LICENSE.txt").read_bytes())
                self.assertFalse((destination / "app/data").exists())


if __name__ == "__main__":
    unittest.main()
