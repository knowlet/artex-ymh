#!/usr/bin/env python3
"""Reviewable ProjectDiscovery release lock refresh; never installs or scans.

--check compares official stable release metadata without changing the lock.
--validate checks an existing lock offline. Downloads are bounded JSON metadata
from api.github.com. SHA-256 values describe release assets, not binary files.
Exit 3 means the lock was committed but reporting the result failed.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "packaging" / "projectdiscovery-lock.json"
TOOLS = ("nuclei", "httpx", "naabu", "katana", "subfinder", "nuclei-templates")
MAX_RESPONSE = 4 * 1024 * 1024
TIMEOUT = 20
HASH_SEMANTICS = (
    "SHA-256 identifies the exact published release asset; it must not be copied "
    "into the installed-binary manifest."
)


class UpdateError(ValueError):
    """An upstream response or lock failed validation."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UpdateError("GitHub metadata redirect refused")


def github_json(url: str) -> dict:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme, parsed.netloc) != ("https", "api.github.com"):
        raise UpdateError("metadata must use https://api.github.com")
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "ARTEX-release-lock-review",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(request, timeout=TIMEOUT) as response:
        body = response.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        raise UpdateError("GitHub metadata exceeds 4 MiB")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise UpdateError("GitHub returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise UpdateError("GitHub metadata must be a JSON object")
    return value


def release_entry(name: str, release: dict, commit: dict) -> dict:
    repository = f"projectdiscovery/{name}"
    tag = release.get("tag_name", "")
    if not isinstance(tag, str) or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise UpdateError(f"{name}: invalid stable release tag")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise UpdateError(f"{name}: draft or prerelease refused")
    sha = commit.get("sha", "")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise UpdateError(f"{name}: invalid source commit")
    release_url = f"https://github.com/{repository}/releases/tag/{tag}"
    if release.get("html_url") != release_url:
        raise UpdateError(f"{name}: unexpected release URL")
    published = release.get("published_at", "")
    if not isinstance(published, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", published
    ):
        raise UpdateError(f"{name}: invalid publication time")
    raw_assets = release.get("assets")
    if not isinstance(raw_assets, list):
        raise UpdateError(f"{name}: missing release assets")
    selected = []
    for asset in raw_assets:
        if not isinstance(asset, dict):
            raise UpdateError(f"{name}: invalid asset metadata")
        filename = asset.get("name", "")
        if not isinstance(filename, str):
            raise UpdateError(f"{name}: invalid asset name")
        if not re.search(r"linux_(amd64|arm64)\.zip$|checksums\.txt$", filename, re.I):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", filename):
            raise UpdateError(f"{name}: unsafe asset name")
        expected_url = f"https://github.com/{repository}/releases/download/{tag}/{filename}"
        if asset.get("browser_download_url") != expected_url:
            raise UpdateError(f"{name}: unexpected asset URL")
        digest = asset.get("digest", "")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise UpdateError(f"{name}: missing SHA-256 asset digest for {filename}")
        selected.append({"name": filename, "url": expected_url, "sha256": digest[7:]})
    names = [asset["name"] for asset in selected]
    if len(names) != len(set(names)):
        raise UpdateError(f"{name}: duplicate release assets")
    if not any(filename.lower().endswith("checksums.txt") for filename in names):
        raise UpdateError(f"{name}: checksum manifest missing")
    if name != "nuclei-templates":
        for arch in ("amd64", "arm64"):
            if sum(filename.endswith(f"linux_{arch}.zip") for filename in names) != 1:
                raise UpdateError(f"{name}: expected one linux/{arch} archive")
    note = (
        "This release publishes a checksums file only; source content is pinned by Git commit, "
        "not by an unverified archive SHA-256."
        if name == "nuclei-templates" and len(selected) == 1
        else "SHA-256 values identify release archives, not extracted binaries."
    )
    return {
        "name": name, "repository": repository, "version": tag, "commit": sha,
        "license": "MIT", "release_url": release_url, "release_published_at": published,
        "source_url": f"https://github.com/{repository}/tree/{sha}",
        "assets": sorted(selected, key=lambda asset: asset["name"]), "artifact_note": note,
    }


def verify_mit_license(metadata: dict, name: str) -> None:
    """Do not carry a previous release's license label onto changed licensing."""
    if metadata.get("encoding") != "base64" or not isinstance(metadata.get("content"), str):
        raise UpdateError(f"{name}: missing source license evidence")
    try:
        text = base64.b64decode("".join(metadata["content"].split()), validate=True).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise UpdateError(f"{name}: invalid source license evidence") from exc
    normalized = " ".join(text.split())
    if not (text.startswith("MIT License")
            and "Permission is hereby granted, free of charge" in normalized
            and "The above copyright notice and this permission notice shall be included" in normalized
            and 'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND' in normalized):
        raise UpdateError(f"{name}: upstream license needs manual review")


def refresh(fetch=github_json) -> dict:
    entries = []
    for name in TOOLS:
        base = f"https://api.github.com/repos/projectdiscovery/{name}"
        release = fetch(f"{base}/releases/latest")
        tag = release.get("tag_name", "")
        if not isinstance(tag, str) or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
            raise UpdateError(f"{name}: invalid release tag")
        commit = fetch(f"{base}/commits/{tag}")
        entry = release_entry(name, release, commit)
        license_metadata = fetch(f"{base}/contents/LICENSE.md?ref={entry['commit']}")
        verify_mit_license(license_metadata, name)
        entries.append(entry)
    return {"schema_version": 1, "artifact_hash_semantics": HASH_SEMANTICS, "tools": entries}


def validate_lock(lock: dict) -> None:
    if not isinstance(lock, dict) or lock.get("schema_version") != 1:
        raise UpdateError("unsupported release lock schema")
    if lock.get("artifact_hash_semantics") != HASH_SEMANTICS:
        raise UpdateError("missing archive hash semantics")
    entries = lock.get("tools")
    if (not isinstance(entries, list) or len(entries) != len(TOOLS)
            or not all(isinstance(entry, dict) for entry in entries)
            or [entry.get("name") for entry in entries] != list(TOOLS)):
        raise UpdateError("release lock must contain the six expected repositories in order")
    for entry in entries:
        if entry.get("repository") != f"projectdiscovery/{entry['name']}" or entry.get("license") != "MIT":
            raise UpdateError("unexpected repository or license in lock")
        assets = entry.get("assets")
        if not isinstance(assets, list):
            raise UpdateError("invalid assets in lock")
        release = {
            "tag_name": entry.get("version"), "draft": False, "prerelease": False,
            "html_url": entry.get("release_url"), "published_at": entry.get("release_published_at"),
            "assets": [{"name": asset.get("name"), "browser_download_url": asset.get("url"),
                        "digest": "sha256:" + str(asset.get("sha256", ""))}
                       for asset in assets if isinstance(asset, dict)],
        }
        if len(release["assets"]) != len(assets):
            raise UpdateError("invalid asset in lock")
        expected = release_entry(entry["name"], release, {"sha": entry.get("commit")})
        if expected != entry:
            raise UpdateError(f"{entry['name']}: inconsistent release lock entry")


def atomic_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as handle:
            temp_path = Path(handle.name)
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def main(argv=None, fetch=github_json) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="compare upstream metadata; never write")
    mode.add_argument("--validate", action="store_true", help="validate the existing lock offline")
    args = parser.parse_args(argv)
    committed = False
    try:
        if args.validate:
            validate_lock(json.loads(args.output.read_text(encoding="utf-8")))
            print("ProjectDiscovery release lock valid (offline; freshness not checked)", flush=True)
            return 0
        latest = refresh(fetch)
        validate_lock(latest)
        if args.check:
            existing = json.loads(args.output.read_text(encoding="utf-8"))
            validate_lock(existing)
            if existing != latest:
                print("ProjectDiscovery release lock differs from upstream; run a refresh and review the diff", flush=True)
                return 1
            print("ProjectDiscovery release lock matches upstream stable release metadata", flush=True)
            return 0
        atomic_write(args.output, latest)
        committed = True
        print(f"Wrote reviewed-version candidate to {args.output}; no tools installed", flush=True)
        return 0
    except (UpdateError, OSError, ValueError, urllib.error.URLError) as exc:
        message = (
            f"ProjectDiscovery release lock committed to {args.output}, but reporting the result failed: {exc}"
            if committed else f"ProjectDiscovery release lock unchanged: {exc}"
        )
        try:
            print(message, file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass  # Preserve the commit-state exit code even if both output streams fail.
        return 3 if committed else 2


if __name__ == "__main__":
    exit_code = main()
    if exit_code == 3:
        # A broken pipe can leave buffered output behind. Close it before the
        # interpreter's shutdown flush would replace the committed exit 3 by 120.
        try:
            sys.stdout.close()
        except (OSError, ValueError):
            pass
    raise SystemExit(exit_code)
