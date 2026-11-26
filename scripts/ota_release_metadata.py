#!/usr/bin/env python3
"""Resolve fork OTA releases and fingerprint code that can migrate persisted data.

Only the main-branch publishing workflow calls ``resolve``.  Stable is an explicit
promotion of a published stable release whose tag is an ancestor of main.  No
workflow input can substitute a repository, image name or arbitrary source ref.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPOSITORY = "knowlet/artex-ymh"
SHA = re.compile(r"[0-9a-f]{40}\Z")
STABLE_TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
PERSISTENCE_PACKAGES = frozenset(("db", "traffic", "skillprovider", "config", "server"))
MIGRATION_MARKERS = re.compile(
    rb"\b(?:create\s+(?:virtual\s+)?(?:table|index|trigger)|alter\s+table|"
    rb"drop\s+(?:table|column|index)|pragma\s+user_version|migrat\w*|seed\w*|automigrate)\b",
    re.IGNORECASE,
)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def schema_fingerprint(root: Path) -> str:
    """Hash names and bytes, not mtimes; exclude tests and ignored build outputs.

    The package set deliberately includes data-access code and on-disk traffic /
    provider formats.  The marker scan additionally includes migration/DDL code
    moved into another production package.  This is a conservative rollback
    boundary, not a promise that every change with a different hash is breaking.
    """
    root = root.resolve()
    required = root / "db/schema.sql"
    if not required.is_file() or required.is_symlink():
        raise ValueError("db/schema.sql must be a regular source file")
    paths = []
    for package in root.iterdir():
        if not package.is_dir() or package.name.startswith(".") or package.name in {
            "web", "node_modules", "dist", "data", "vendor",
        }:
            continue
        for path in package.rglob("*"):
            if path.suffix not in {".go", ".sql"} or path.name.endswith("_test.go"):
                continue
            rel = path.relative_to(root)
            if any(part.startswith(".") or part in {"testdata", "node_modules"} for part in rel.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"migration source must not be a symlink: {rel}")
            if not path.is_file():
                continue
            data = path.read_bytes()
            if path.suffix == ".sql" or rel.parts[0] in PERSISTENCE_PACKAGES or MIGRATION_MARKERS.search(data):
                paths.append((rel.as_posix(), data))
    # Root-level production files are uncommon but must not hide DDL.
    for path in root.iterdir():
        if path.suffix in {".go", ".sql"} and not path.name.endswith("_test.go"):
            if path.is_symlink():
                raise ValueError(f"migration source must not be a symlink: {path.name}")
            if path.is_file() and MIGRATION_MARKERS.search(data := path.read_bytes()):
                paths.append((path.name, data))
    digest = hashlib.sha256(b"artex-ota-schema-v1\0")
    for name, data in sorted(paths):
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(str(len(data)).encode("ascii") + b"\0")
        digest.update(data)
    return digest.hexdigest()


def resolve(event_name: str, event: dict, ref: str, sha: str, *, repository: str,
            release_lookup=None, git_command=git) -> dict[str, str]:
    if repository != REPOSITORY:
        raise ValueError("OTA publishing is restricted to knowlet/artex-ymh")
    if not SHA.fullmatch(sha):
        raise ValueError("source must be a full lowercase commit SHA")
    if event_name == "pull_request":
        if not re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref):
            raise ValueError("PR validation requires a merge ref")
        return {"commit": sha, "channel": "main", "version": f"pr-{sha[:12]}", "publish": "false"}
    if ref != "refs/heads/main" or event_name not in {"push", "schedule", "workflow_dispatch"}:
        raise ValueError("publishing must run from the main-branch workflow")
    inputs = event.get("inputs") or {}
    channel = "nightly" if event_name == "schedule" else "main"
    if event_name == "workflow_dispatch":
        channel = inputs.get("channel", "main")
    if channel not in {"main", "nightly", "stable"}:
        raise ValueError("unsupported OTA channel")
    tag = inputs.get("release_tag", "")
    if channel != "stable" and tag:
        raise ValueError("release_tag is only valid for stable promotion")
    if channel == "stable":
        if not isinstance(tag, str) or not STABLE_TAG.fullmatch(tag):
            raise ValueError("stable promotion requires a vMAJOR.MINOR.PATCH tag")
        if release_lookup is None:
            def release_lookup(name):
                return json.loads(subprocess.check_output(
                    ["gh", "api", f"repos/{REPOSITORY}/releases/tags/{name}"],
                    text=True, timeout=30,
                ))
        release = release_lookup(tag)
        if (release.get("tag_name") != tag or release.get("draft") is not False
                or release.get("prerelease") is not False or not release.get("published_at")):
            raise ValueError("stable tag must identify a published, non-draft, non-prerelease release")
        sha = git_command("rev-parse", "--verify", "--end-of-options", f"refs/tags/{tag}^{{commit}}")
        if not SHA.fullmatch(sha):
            raise ValueError("release tag did not resolve to a commit")
        git_command("merge-base", "--is-ancestor", sha, "refs/remotes/origin/main")
        version = tag
    else:
        version = f"{channel}-{sha[:12]}"
    return {"commit": sha, "channel": channel, "version": version, "publish": "true"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fingerprint = sub.add_parser("schema")
    fingerprint.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    sub.add_parser("resolve")
    args = parser.parse_args()
    try:
        if args.command == "schema":
            print(schema_fingerprint(args.root))
        else:
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
            result = resolve(os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_REF"],
                             os.environ["GITHUB_SHA"], repository=os.environ["GITHUB_REPOSITORY"])
            # All values above are constructed from fixed choices / strict regexes.
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                for key, value in result.items():
                    output.write(f"{key}={value}\n")
            print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"OTA metadata: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
