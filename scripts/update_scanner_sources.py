#!/usr/bin/env python3
"""Track pinned source revisions of actively maintained security test projects.

Metadata only: does not install scanners, execute PoCs, change ARTEX permissions,
or claim that a CVE/template is relevant to any particular target. New sources
are allowlisted and must pass provenance and license metadata checks.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys

import update_projectdiscovery as github

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "packaging/scanner-source-index.json"
SCOPE = "Pinned public security testing projects; metadata only, not installed or executable."
# The PHP2Shell specialist has not published GitHub Releases: pin its master
# commit. Others are pinned to their latest stable release and commit.
SOURCES = (
    ("assetnote/php2shell-scanner", "MIT", "commit", "php2shell-detection"),
    ("google/osv-scanner", "Apache-2.0", "release", "dependency-scanning"),
    ("aquasecurity/trivy", "Apache-2.0", "release", "container-sbom-iac"),
    ("zaproxy/zaproxy", "Apache-2.0", "release", "web-security-testing"),
    ("ffuf/ffuf", "MIT", "release", "web-fuzzing"),
)
HASH = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def expect_object(value, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(label + " must be an object")
    return value


def validate(data: dict) -> None:
    expect_object(data, "index")
    if (data.get("schema_version") != 1 or data.get("scope") != SCOPE
            or not isinstance(data.get("projects"), list)
            or len(data["projects"]) != len(SOURCES)):
        raise ValueError("invalid source-index schema")
    for row, (repository, license_name, tracking, role) in zip(data["projects"], SOURCES):
        expect_object(row, repository)
        if set(row) != {
            "repository", "license", "tracking", "role", "ref", "commit",
            "source_url", "released_at",
        }:
            raise ValueError(repository + ": unrecognized or missing fields")
        if any(row[k] != v for k, v in (
            ("repository", repository), ("license", license_name),
            ("tracking", tracking), ("role", role),
        )):
            raise ValueError(repository + ": project allowlist does not match")
        sha, ref = row.get("commit"), row.get("ref")
        if not isinstance(sha, str) or not HASH.fullmatch(sha):
            raise ValueError(repository + ": invalid commit SHA")
        if not isinstance(ref, str) or (
            ref != "master" if tracking == "commit" else not TAG.fullmatch(ref)
        ):
            raise ValueError(repository + ": invalid source ref")
        if row["source_url"] != f"https://github.com/{repository}/tree/{sha}":
            raise ValueError(repository + ": unexpected source URL")
        stamp = row.get("released_at")
        if tracking == "commit":
            if stamp is not None:
                raise ValueError(repository + ": commit source cannot imply release date")
        elif (not isinstance(stamp, str) or not DATE.fullmatch(stamp)):
            raise ValueError(repository + ": invalid publication timestamp")
        if isinstance(stamp, str):
            dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")


def refresh(fetch=github.github_json) -> dict:
    records = []
    for repository, license_name, tracking, role in SOURCES:
        base = "https://api.github.com/repos/" + repository
        meta = expect_object(fetch(base), repository)
        if (meta.get("full_name") != repository or meta.get("archived") is not False
                or meta.get("disabled") is not False
                or not isinstance(meta.get("license"), dict)
                or meta["license"].get("spdx_id") != license_name):
            raise ValueError(repository + ": identity/license/maintenance requires manual review")
        branch = meta.get("default_branch")
        if not isinstance(branch, str) or not re.fullmatch(r"[a-z0-9_-]{1,64}", branch):
            raise ValueError(repository + ": invalid default branch")
        if tracking == "commit":
            if branch != "master":
                raise ValueError(repository + ": tracked default branch changed; review required")
            ref, published = branch, None
        else:
            release = expect_object(fetch(base + "/releases/latest"), repository + " release")
            ref = release.get("tag_name")
            if (not isinstance(ref, str) or not TAG.fullmatch(ref)
                    or release.get("draft") is not False or release.get("prerelease") is not False
                    or release.get("html_url") != f"https://github.com/{repository}/releases/tag/{ref}"):
                raise ValueError(repository + ": latest release identity invalid")
            published = release.get("published_at")
        commit = expect_object(fetch(base + "/commits/" + ref), repository + " commit")
        sha = commit.get("sha")
        if not isinstance(sha, str) or not HASH.fullmatch(sha):
            raise ValueError(repository + ": missing full commit SHA")
        records.append({
            "repository": repository, "license": license_name, "tracking": tracking,
            "role": role, "ref": ref, "commit": sha,
            "source_url": f"https://github.com/{repository}/tree/{sha}",
            "released_at": published,
        })
    result = {"schema_version": 1, "scope": SCOPE, "projects": records}
    validate(result)
    return result


def main(argv=None, fetch=github.github_json) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--validate", action="store_true", help="validate local source metadata offline")
    mode.add_argument("--check", action="store_true", help="compare without writing")
    args = parser.parse_args(argv)
    try:
        previous = None
        if args.output.exists():
            previous = json.loads(args.output.read_text(encoding="utf-8"))
            validate(previous)
        if args.validate:
            if previous is None:
                raise ValueError("index absent")
            print("scanner source metadata valid (freshness not checked online)")
            return 0
        newest = refresh(fetch)
        if args.check:
            print("current" if previous == newest else "scanner source update available")
            return 0 if previous == newest else 1
        if previous == newest:
            print("scanner source metadata current")
            return 0
        github.atomic_write(args.output, newest)
        print("Updated five scanner source references; no software downloaded or executed")
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("scanner source update failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
