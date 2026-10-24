#!/usr/bin/env python3
"""Build an offline integrity manifest for ARTEX's existing intelligence files.

The manifest binds local bytes, not upstream authenticity. No downloads, tool
installation, scans, or findings writes occur. Publish it beside both inputs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

import update_nuclei_index as nuclei
import update_projectdiscovery as releases
import update_vulnerability_intel as kev

ROOT = Path(__file__).resolve().parents[1]
KIND = "artex-discovery-intelligence"
SCOPE = "CISA KEV and ProjectDiscovery release metadata; not complete CVE List or target evidence."
KEV_NAME = "vulnerability-intel.json"
RELEASE_NAME = "projectdiscovery-lock.json"
NUCLEI_NAME = "nuclei-cve-index.json"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_LOCK_BYTES = 1024 * 1024


def read_source(root: Path, name: str, limit: int) -> bytes:
    """Read one bounded regular input, refusing symlink escapes and special files."""
    canonical_root = root.resolve(strict=True)
    path = (canonical_root / name).resolve(strict=True)
    if not path.is_relative_to(canonical_root):
        raise ValueError("source file escapes packaging directory: " + name)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("source is not a regular file: " + name)
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("source is empty or exceeds size limit: " + name)
    return raw


def official_kev(raw: bytes) -> dict:
    document = kev.parse_json(raw)
    kev.validate_catalog(raw)
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1 or document.get("license") != "CC0-1.0":
        raise ValueError("KEV snapshot schema or license is unsupported")
    if document.get("scope") != "CISA KEV only; not the complete CVE List":
        raise ValueError("KEV scope is missing or inconsistent")
    source = document.get("source")
    if not isinstance(source, dict) or source.get("kind") != "official-github":
        raise ValueError("data pack requires an official-source KEV snapshot")
    commit = source.get("commit")
    sha = source.get("sha256")
    if not isinstance(commit, str) or not kev.COMMIT.fullmatch(commit):
        raise ValueError("KEV source requires a full commit SHA")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ValueError("KEV raw source SHA-256 is invalid")
    expected_url = kev.RAW_BASE + commit + "/" + kev.SOURCE_FILE
    expected_license = "https://github.com/cisagov/kev-data/blob/" + commit + "/LICENSE"
    if (source.get("repository") != kev.REPOSITORY or source.get("url") != expected_url
            or document.get("license_url") != expected_license):
        raise ValueError("KEV official source or license URL is inconsistent")
    return document


def source_entry(name: str, path: str, raw: bytes, license_name: str, source_date: str) -> dict:
    return {"name": name, "path": path, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "license": license_name, "source_date": source_date}


def build(packaging_dir: Path) -> dict:
    kev_raw = read_source(packaging_dir, KEV_NAME, kev.MAX_BYTES)
    lock_raw = read_source(packaging_dir, RELEASE_NAME, MAX_LOCK_BYTES)
    nuclei_raw = read_source(packaging_dir, NUCLEI_NAME, kev.MAX_BYTES)
    catalog = official_kev(kev_raw)
    lock = kev.parse_json(lock_raw)
    releases.validate_lock(lock)
    nuclei_document = kev.parse_json(nuclei_raw)
    nuclei.validate_index(nuclei_document)
    nuclei_source = nuclei_document.get("source")
    if (not isinstance(nuclei_source, dict) or nuclei_source.get("kind") != "official-github"
            or nuclei_document.get("license") != "MIT"):
        raise ValueError("data pack requires an official-source MIT template index")
    if nuclei_document.get("license_file") != "discovery/NUCLEI-LICENSE.txt":
        raise ValueError("template index must name its retained local MIT notice")
    nuclei.verify_notice(read_source(packaging_dir, "discovery/NUCLEI-LICENSE.txt", 128 * 1024))
    templates_release = next(entry for entry in lock["tools"] if entry["name"] == "nuclei-templates")
    if (nuclei_source.get("commit") != templates_release["commit"]
            or nuclei_source.get("release") != templates_release["version"]
            or nuclei_source.get("release_published_at") != templates_release["release_published_at"]):
        raise ValueError("template index does not match the locked templates release")
    nuclei_date = nuclei_document["source"]["release_published_at"]
    try:
        if dt.datetime.fromisoformat(nuclei_date.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("template index publication time requires a timezone")
    except (ValueError, AttributeError) as error:
        raise ValueError("invalid template index publication time") from error
    dated = []
    for entry in lock["tools"]:
        stamp = entry["release_published_at"]
        try:
            dated.append((dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")), stamp))
        except ValueError as error:
            raise ValueError("invalid ProjectDiscovery publication time") from error
    latest = max(dated)[1]
    return {"schema_version": 1, "kind": KIND, "scope": SCOPE, "files": [
        source_entry("cisa-kev", KEV_NAME, kev_raw, "CC0-1.0", catalog["dateReleased"]),
        source_entry("projectdiscovery-releases", RELEASE_NAME, lock_raw, "MIT", latest),
        source_entry("nuclei-cve-index", NUCLEI_NAME, nuclei_raw, "MIT", nuclei_date),
    ]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packaging-dir", type=Path, default=ROOT / "packaging")
    parser.add_argument("--output", type=Path, help="manifest beside inputs; default discovery-data-manifest.json")
    parser.add_argument("--check", action="store_true", help="offline comparison; exit 1 for changed/missing manifest")
    args = parser.parse_args(argv)
    committed = False
    try:
        root = args.packaging_dir.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("packaging directory is not a directory")
        output = args.output or root / "discovery-data-manifest.json"
        if output.parent.resolve(strict=True) != root or output.name in {KEV_NAME, RELEASE_NAME, NUCLEI_NAME}:
            raise ValueError("manifest must be a separate file beside the three inputs")
        if output.is_symlink():
            raise ValueError("manifest destination must not be a symlink")
        document = build(root)
        if args.check:
            if not output.exists():
                print("data manifest update available", flush=True)
                return 1
            existing = read_source(root, output.name, MAX_MANIFEST_BYTES)
            if kev.parse_json(existing) != document:
                print("data manifest update available", flush=True)
                return 1
            print("data manifest current (offline local integrity only)", flush=True)
            return 0
        kev.atomic_write(output, kev.encoded(document))
        committed = True
        print("wrote data manifest; input data unchanged; no network access", flush=True)
        return 0
    except (ValueError, OSError) as error:
        message = ("data manifest committed, but success report failed: " if committed
                   else "data manifest unchanged: ") + str(error)
        try:
            print(message, file=sys.stderr, flush=True)
        except (ValueError, OSError):
            pass  # The exit code remains authoritative if both output streams fail.
        return 3 if committed else 2


if __name__ == "__main__":
    exit_code = main()
    if exit_code == 3:
        # Flush failures can leave buffered bytes that Python would flush again
        # at shutdown, replacing the committed-state exit code with exit 120.
        # Only the real CLI closes its stream; imported main() leaves callers'
        # output streams under their control.
        try:
            sys.stdout.close()
        except (OSError, ValueError):
            pass
    raise SystemExit(exit_code)
