"""No-network tests for allowlisted scanner project source tracking."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

import update_scanner_sources as sources


def mock_responses():
    items = {}
    for repository, license_name, tracking, _ in sources.SOURCES:
        base = "https://api.github.com/repos/" + repository
        branch = "master" if tracking == "commit" else "main"
        items[base] = {
            "full_name": repository, "archived": False, "disabled": False,
            "default_branch": branch, "license": {"spdx_id": license_name},
        }
        if tracking == "commit":
            tag, published = branch, None
        else:
            tag, published = "v2.3.0", "2026-10-21T12:30:00Z"
            items[base + "/releases/latest"] = {
                "tag_name": tag, "draft": False, "prerelease": False,
                "html_url": f"https://github.com/{repository}/releases/tag/{tag}",
                "published_at": published,
            }
        items[base + "/commits/" + tag] = {"sha": "1" * 40}
    return items


class ScannerSourceTests(unittest.TestCase):
    def setUp(self):
        self.payloads = mock_responses()
        self.called = []

    def fetch(self, url):
        self.called.append(url)
        return copy.deepcopy(self.payloads[url])

    def test_all_sources_are_allowlisted_and_reproducibly_pinned(self):
        result = sources.refresh(self.fetch)
        sources.validate(result)
        self.assertEqual(len(result["projects"]), 5)
        self.assertEqual(result["projects"][0]["ref"], "master")
        self.assertIsNone(result["projects"][0]["released_at"])
        self.assertEqual(result["projects"][1]["tracking"], "release")
        self.assertEqual(len(self.called), 14)
        self.assertEqual(sources.refresh(self.fetch), result)

    def test_changed_repo_identity_fails_closed(self):
        base = "https://api.github.com/repos/assetnote/php2shell-scanner"
        self.payloads[base]["full_name"] = "attacker/fork"
        with self.assertRaisesRegex(ValueError, "identity/license"):
            sources.refresh(self.fetch)

    def test_license_or_archival_change_fails_closed(self):
        base = "https://api.github.com/repos/google/osv-scanner"
        self.payloads[base]["license"]["spdx_id"] = "UNKNOWN"
        with self.assertRaisesRegex(ValueError, "identity/license"):
            sources.refresh(self.fetch)
        self.payloads = mock_responses()
        self.payloads[base]["archived"] = True
        with self.assertRaisesRegex(ValueError, "identity/license"):
            sources.refresh(self.fetch)

    def test_invalid_release_or_commit_metadata_rejected(self):
        base = "https://api.github.com/repos/google/osv-scanner"
        self.payloads[base + "/releases/latest"]["prerelease"] = True
        with self.assertRaisesRegex(ValueError, "release identity invalid"):
            sources.refresh(self.fetch)
        self.payloads = mock_responses()
        self.payloads[base + "/commits/v2.3.0"]["sha"] = "truncated"
        with self.assertRaisesRegex(ValueError, "missing full commit SHA"):
            sources.refresh(self.fetch)

    def test_local_index_does_not_accept_injected_sources(self):
        result = sources.refresh(self.fetch)
        modified = copy.deepcopy(result)
        modified["projects"].append({"repository": "attacker/repo"})
        with self.assertRaisesRegex(ValueError, "invalid source-index"):
            sources.validate(modified)
        modified = copy.deepcopy(result)
        modified["projects"][1]["source_url"] = "https://evil.invalid/tool"
        with self.assertRaisesRegex(ValueError, "unexpected source URL"):
            sources.validate(modified)

    def test_offline_validate_and_failure_keep_existing_file(self):
        result = sources.refresh(self.fetch)
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / "sources.json"
            dest.write_text(json.dumps(result), encoding="utf-8")
            original = dest.read_bytes()
            def fail(url):
                raise AssertionError("must not access the network")
            self.assertEqual(sources.main(["--validate", "--output", str(dest)], fail), 0)
            self.assertEqual(sources.main(["--check", "--output", str(dest)], self.fetch), 0)
            self.payloads = mock_responses()
            self.payloads["https://api.github.com/repos/ffuf/ffuf"]["disabled"] = True
            self.assertEqual(sources.main(["--output", str(dest)], self.fetch), 2)
            self.assertEqual(dest.read_bytes(), original)

    def test_initial_repository_index_is_valid(self):
        committed = json.loads(sources.DEFAULT_OUTPUT.read_text(encoding="utf-8"))
        sources.validate(committed)


if __name__ == "__main__":
    unittest.main()
