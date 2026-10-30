"""Offline regression tests for synchronized scanner source locks."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import sync_projectdiscovery_bundle as sync


def fixtures():
    return (
        json.loads(sync.DEFAULT_RELEASES.read_text(encoding="utf-8")),
        json.loads(sync.DEFAULT_SOURCES.read_text(encoding="utf-8")),
        json.loads(sync.DEFAULT_MANIFEST.read_text(encoding="utf-8")),
    )


def official_license():
    # Test fixture is the retained MIT notice, not a live network response.
    notice = (sync.ROOT / "packaging/discovery/NUCLEI-LICENSE.txt").read_bytes()
    digest = hashlib.sha1(
        b"blob " + str(len(notice)).encode("ascii") + b"\0" + notice
    ).hexdigest()
    return {"encoding": "base64", "content": base64.b64encode(notice).decode(),
            "sha": digest}


class BundlePinSyncTests(unittest.TestCase):
    def setUp(self):
        self.releases, self.bundle, self.manifest = fixtures()
        self.calls = []

    def fetch(self, url):
        self.calls.append(url)
        return official_license()

    def test_updates_only_reviewed_three_and_preserves_other_pins(self):
        updated = sync.synchronize(self.releases, self.bundle, self.fetch)
        sync.validate_consistency(self.releases, updated, self.manifest)
        self.assertEqual(len(self.calls), 3)
        for url in self.calls:
            self.assertIn("/contents/LICENSE.md?ref=", url)
        self.assertEqual(updated["external"], self.bundle["external"])
        self.assertEqual(updated["bundled"]["mimikatz"], self.bundle["bundled"]["mimikatz"])
        self.assertEqual(
            sync.unique_download(updated, "mimikatz.exe"),
            sync.unique_download(self.bundle, "mimikatz.exe"),
        )
        self.assertEqual(updated["bundled"]["naabu"]["upstream"],
                         next(x["source_url"] for x in self.releases["tools"]
                              if x["name"] == "naabu"))

    def test_fails_closed_on_license_body_identity_mismatch(self):
        def bad(url):
            data = official_license()
            data["sha"] = "f" * 40
            return data

        with self.assertRaisesRegex(ValueError, "disagrees"):
            sync.synchronize(self.releases, self.bundle, bad)
        self.assertEqual(
            sync.unique_download(self.bundle, "naabu")["sha256"],
            sync.expected_asset(self.releases["tools"][2], "naabu")["sha256"],
        )

    def test_missing_sha_and_changed_license_not_accepted(self):
        data = official_license()
        data.pop("sha")
        with self.assertRaisesRegex(ValueError, "missing Git blob"):
            sync.synchronize(self.releases, self.bundle, lambda url: data)
        data = official_license()
        data["content"] = base64.b64encode(b"Not MIT\n").decode()
        with self.assertRaises(Exception):
            sync.synchronize(self.releases, self.bundle, lambda url: data)

    def test_rejects_unpinned_or_duplicate_release_assets(self):
        modified = copy.deepcopy(self.releases)
        entry = next(row for row in modified["tools"] if row["name"] == "naabu")
        entry["assets"] = [a for a in entry["assets"] if not a["name"].endswith("linux_amd64.zip")]
        with self.assertRaises(ValueError):
            sync.synchronize(modified, self.bundle, self.fetch)

    def test_detects_wrong_binary_digest_and_license_reference(self):
        candidate = sync.synchronize(self.releases, self.bundle, self.fetch)
        sync.unique_download(candidate, "httpx")["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binary URL/hash"):
            sync.validate_consistency(self.releases, candidate, self.manifest)
        candidate = sync.synchronize(self.releases, self.bundle, self.fetch)
        sync.unique_download(candidate, "licenses/katana/LICENSE.md")["url"] += "bad"
        with self.assertRaisesRegex(ValueError, "license is not pinned"):
            sync.validate_consistency(self.releases, candidate, self.manifest)

    def test_cli_offline_validate_does_not_call_network(self):
        candidate = sync.synchronize(self.releases, self.bundle, self.fetch)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            inputs = []
            for filename, value in (
                ("projectdiscovery.json", self.releases),
                ("sources.json", candidate),
                ("manifest.json", self.manifest),
            ):
                path = root / filename
                path.write_text(json.dumps(value), encoding="utf-8")
                inputs.append(str(path))
            def fail(url):
                raise AssertionError("offline validation used the network")
            args = ["--validate", "--release-lock", inputs[0],
                    "--sources", inputs[1], "--manifest", inputs[2]]
            self.assertEqual(sync.main(args, fetch=fail), 0)
            modified = copy.deepcopy(candidate)
            modified["bundled"]["katana"]["version"] = "v0.0.0"
            Path(inputs[1]).write_text(json.dumps(modified), encoding="utf-8")
            self.assertEqual(sync.main(args, fetch=fail), 2)


if __name__ == "__main__":
    unittest.main()
