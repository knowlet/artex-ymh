#!/usr/bin/env python3
"""Sync pinned ProjectDiscovery scanner archives into ARTEX's reviewable tool bundle.

Only naabu/httpx/katana are currently bundled. Other ProjectDiscovery tools
remain explicitly external. This script never downloads or executes binaries.
All release hashes come from the validated upstream release lock; license bytes
and Git blob identity are verified against the GitHub API before publishing.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

import build_tools_bundle
import update_projectdiscovery as releases

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RELEASES = ROOT / "packaging/projectdiscovery-lock.json"
DEFAULT_SOURCES = ROOT / "packaging/tools-sources.lock.json"
DEFAULT_MANIFEST = ROOT / "packaging/tools-manifest.json"
BUNDLED = ("naabu", "httpx", "katana")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def unique_download(lock: dict, path: str) -> dict:
    matches = [
        spec for spec in lock.get("downloads", [])
        if any(isinstance(item, dict) and item.get("path") == path
               for item in spec.get("files", []))
    ]
    if len(matches) != 1 or len(matches[0].get("files", [])) != 1:
        raise ValueError("expected one isolated download for " + path)
    return matches[0]


def expected_asset(entry: dict, name: str) -> dict:
    filename = f"{name}_{entry['version'].removeprefix('v')}_linux_amd64.zip"
    matches = [a for a in entry["assets"] if a["name"] == filename]
    if len(matches) != 1:
        raise ValueError(name + ": missing unique Linux amd64 release artifact")
    return matches[0]


def validate_consistency(release_lock: dict, bundle: dict, manifest: dict) -> None:
    releases.validate_lock(release_lock)
    build_tools_bundle.validate_lock(bundle, manifest)
    releases_by_name = {entry["name"]: entry for entry in release_lock["tools"]}
    for name in BUNDLED:
        entry = releases_by_name[name]
        desired = expected_asset(entry, name)
        bundled = bundle["bundled"][name]
        if (bundled.get("version") != entry["version"]
                or bundled.get("upstream") != entry["source_url"]
                or bundled.get("license_files") != [f"licenses/{name}/LICENSE.md"]):
            raise ValueError(name + ": bundled metadata does not match release lock")
        binary = unique_download(bundle, name)
        if (binary.get("url") != desired["url"]
                or binary.get("sha256") != desired["sha256"]
                or binary.get("format") != "zip"
                or binary["files"][0].get("member") != name):
            raise ValueError(name + ": binary URL/hash does not match approved release lock")
        license_spec = unique_download(bundle, f"licenses/{name}/LICENSE.md")
        license_url = (
            f"https://raw.githubusercontent.com/projectdiscovery/{name}/"
            f"{entry['commit']}/LICENSE.md"
        )
        if (license_spec.get("url") != license_url
                or license_spec.get("format") != "raw"
                or not isinstance(license_spec.get("git_blob_sha1"), str)
                or not HEX40.fullmatch(license_spec["git_blob_sha1"])):
            raise ValueError(name + ": source license is not pinned to approved commit")


def synchronize(release_lock: dict, bundle: dict, fetch=releases.github_json) -> dict:
    releases.validate_lock(release_lock)
    output = copy.deepcopy(bundle)
    rows = {entry["name"]: entry for entry in release_lock["tools"]}
    for name in BUNDLED:
        entry = rows[name]
        archive = expected_asset(entry, name)
        url = (
            f"https://api.github.com/repos/projectdiscovery/{name}/"
            f"contents/LICENSE.md?ref={entry['commit']}"
        )
        metadata = fetch(url)
        releases.verify_mit_license(metadata, name)
        blob_hash = metadata.get("sha")
        if not isinstance(blob_hash, str) or not HEX40.fullmatch(blob_hash):
            raise ValueError(name + ": license response missing Git blob SHA")
        try:
            license_raw = base64.b64decode(
                "".join(metadata["content"].split()), validate=True
            )
        except (KeyError, ValueError, binascii.Error) as error:
            raise ValueError(name + ": invalid license body") from error
        observed = hashlib.sha1(
            b"blob " + str(len(license_raw)).encode("ascii") + b"\0" + license_raw
        ).hexdigest()
        if observed != blob_hash:
            raise ValueError(name + ": license content disagrees with Git blob SHA")
        output["bundled"][name]["version"] = entry["version"]
        output["bundled"][name]["upstream"] = entry["source_url"]
        binary = unique_download(output, name)
        binary["url"], binary["sha256"] = archive["url"], archive["sha256"]
        license_spec = unique_download(output, f"licenses/{name}/LICENSE.md")
        license_spec["url"] = (
            f"https://raw.githubusercontent.com/projectdiscovery/{name}/"
            f"{entry['commit']}/LICENSE.md"
        )
        license_spec["git_blob_sha1"] = blob_hash
    return output


def read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(str(path) + ": expected JSON object")
    return data


def main(argv=None, fetch=releases.github_json) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-lock", type=Path, default=DEFAULT_RELEASES)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--validate", action="store_true", help="offline lock consistency; no network")
    mode.add_argument("--check", action="store_true", help="compare upstream pins without writing")
    args = parser.parse_args(argv)
    try:
        lock = read_json(args.release_lock)
        source = read_json(args.sources)
        manifest = read_json(args.manifest)
        if args.validate:
            validate_consistency(lock, source, manifest)
            print("ProjectDiscovery bundled scanners agree with release lock (offline)")
            return 0
        latest = synchronize(lock, source, fetch)
        validate_consistency(lock, latest, manifest)
        if args.check:
            print("current" if latest == source else "bundle source update available")
            return 0 if latest == source else 1
        if latest == source:
            print("ProjectDiscovery bundle source pins already current")
            return 0
        releases.atomic_write(args.sources, latest)
        print("Updated three reviewed scanner source pins; no binaries installed")
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("ProjectDiscovery bundle synchronization failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
