#!/usr/bin/env python3
"""Build/install the separately reviewed local-scanner add-on, never execute it.

Reuses build_tools_bundle.py's archive validation, source verification and
reproducible tar writer. Network is opt-in; existing deployments are untouched.
The default is to require all pinned inputs in the URL-keyed source cache.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "localscan/sources.lock.json"


def check_registry(lock, registry):
    projects = registry.get("projects", [])
    for name, spec in lock["bundled"].items():
        matches = [p for p in projects if p.get("repository") == spec["repository"]]
        if len(matches) != 1 or any(matches[0].get(k) != spec[v] for k, v in
                                   (("ref", "version"), ("commit", "commit"), ("license", "license"))):
            raise ValueError("reviewed installation pins differ from source registry: " + name)


def install_files(files, destination):
    """Only publish an absent, separately selected installation directory."""
    destination = Path(destination)
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ValueError("installation requires an absent absolute destination")
    parent = destination.parent
    if not parent.is_dir() or any(p.is_symlink() for p in (parent, *parent.parents)):
        raise ValueError("installation parent must exist and cannot contain symlinks")
    temporary = Path(tempfile.mkdtemp(prefix=".local-scanners-", dir=parent))
    try:
        for name, (data, mode) in sorted(files.items()):
            parts = name.split("/")
            if any(p in ("", ".", "..") for p in parts) or "\\" in name:
                raise ValueError("unsafe install path")
            target = temporary.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
        # No hostile concurrent same-account mutation guarantee. Refuse a
        # pre-existing destination; this does not modify any production store.
        if destination.exists() or destination.is_symlink():
            raise ValueError("installation destination appeared during staging")
        os.rename(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--download", action="store_true", help="allow official HTTPS source downloads")
    parser.add_argument("--bundle", type=Path, help="write a deterministic, standalone add-on archive")
    parser.add_argument("--install-dir", type=Path, help="publish verified sources in a new isolated directory")
    parser.add_argument("--validate", action="store_true", help="only check lock/registry; no network or execution")
    args = parser.parse_args()
    try:
        # Trusted sibling builder, already covered by the original bundle tests.
        import build_tools_bundle as bundle
        lock = json.loads(LOCK.read_bytes())
        check_registry(lock, json.loads((ROOT / "packaging/scanner-source-index.json").read_bytes()))
        manifest = {"tools": [{"name": name, "path": "tools/" + name, "sha256": "", "version": spec["version"]}
                              for name, spec in sorted(lock["bundled"].items())]}
        bundle.validate_lock(lock, manifest)
        if args.validate:
            print("Validated reviewed OSV/Trivy install pins against the #10 source registry")
            return 0
        if args.bundle is None and args.install_dir is None:
            raise ValueError("select --bundle and/or --install-dir")
        if args.bundle is not None and (args.bundle.exists() or args.bundle.is_symlink()):
            raise ValueError("refusing to overwrite an existing bundle")
        if args.install_dir is not None:
            destination = Path(args.install_dir)
            if not destination.is_absolute() or destination.exists() or destination.is_symlink():
                raise ValueError("installation requires an absent absolute destination")
            parent = destination.parent
            if not parent.is_dir() or any(part.is_symlink() for part in (parent, *parent.parents)):
                raise ValueError("installation parent must exist and cannot contain symlinks")
        specs = {}
        for source in lock["downloads"]:
            specs[source["url"]] = source
            if source.get("checksums"):
                specs[source["checksums"]["url"]] = source["checksums"]

        def fetch(url):
            if url not in specs:
                raise ValueError("unreviewed source URL")
            if args.download:
                data = bundle.download(url, args.cache)
            else:
                cache_file = args.cache / hashlib.sha256(url.encode()).hexdigest()
                if cache_file.is_symlink() or not cache_file.is_file():
                    raise ValueError("offline source cache missing: " + url)
                with cache_file.open("rb") as stream:
                    data = bundle.read_limited(stream)
            # Enforce BOTH release API digest and pinned checksum-list digest.
            bundle.check_hash(data, specs[url])
            return data

        with contextlib.redirect_stdout(sys.stderr):
            files = bundle.build_files(lock, manifest, (ROOT / "docs/LOCAL-SCANNERS.md").read_bytes(), fetch)
        for name, spec in lock["bundled"].items():
            for license_path in spec["license_files"]:
                if b"Apache License" not in files[license_path][0] or b"Version 2.0" not in files[license_path][0]:
                    raise ValueError("unexpected license text")
        if args.bundle is not None:
            bundle.write_archive(files, args.bundle, epoch=0)
            bundle.verify_archive(args.bundle)
            archive_hash = hashlib.sha256(args.bundle.read_bytes()).hexdigest()
            print(json.dumps({"bundle": str(args.bundle), "sha256": archive_hash}))
        if args.install_dir is not None:
            install_files(files, args.install_dir)
            print(json.dumps({"installation": str(args.install_dir), "tools": json.loads(files["tools-manifest.json"][0])["tools"],
                              "execution": "none; binaries staged only"}))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("local-scanner installation failed: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
