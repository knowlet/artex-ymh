#!/usr/bin/env python3
"""Build the documented Linux/amd64 tool bundle from reviewed, pinned inputs.

Only the Python standard library is required. Downloaded tools are never run.
No deployment data, credentials, virtualenvs, or automatic tool registrations
are included. See packaging/TOOLS.md for installation and trust boundaries.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1024 * 1024 * 1024
MAX_MEMBERS = 10000
HOSTS = {"github.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
METADATA = {"tools-manifest.json", "bundle.json", "SHA256SUMS", "INSTALL.md", "sources.lock.json"}


class BundleError(ValueError):
    """Invalid input; never publish a partial bundle."""


def safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise BundleError(f"unsafe path: {value!r}")
    parts = value.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in parts) or any(ord(c) < 32 for c in value):
        raise BundleError(f"unsafe path: {value!r}")
    return "/".join(parts)


def checked_url(url: str) -> str:
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname not in HOSTS or p.username or p.password or p.port not in (None, 443):
        raise BundleError(f"unsupported download URL: {url}")
    return url


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_limited(stream, limit: int = LIMIT) -> bytes:
    chunks, size = [], 0
    while True:
        block = stream.read(min(1024 * 1024, limit - size + 1))
        if not block:
            break
        size += len(block)
        if size > limit:
            raise BundleError(f"input exceeds {limit} bytes")
        chunks.append(block)
    return b"".join(chunks)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_hash(data: bytes, spec: dict) -> None:
    if spec.get("sha256") and sha256(data) != spec["sha256"]:
        raise BundleError(f"SHA-256 mismatch: {spec.get('url', spec.get('member', 'input'))}")
    if spec.get("git_blob_sha1"):
        # Source-file identity as returned by GitHub's Git Trees API. Not a
        # plain SHA-1 of the file, and not represented as a SHA-256 pin.
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != spec["git_blob_sha1"]:
            raise BundleError(f"Git blob mismatch: {spec.get('url', 'input')}")


def download(url: str, cache: Path) -> bytes:
    checked_url(url)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / sha256(url.encode())
    if target.exists():
        with target.open("rb") as stream:
            return read_limited(stream)
    opener = build_opener(SafeRedirect())
    for attempt in range(3):
        try:
            # Never send GITHUB_TOKEN or other credentials to download hosts.
            req = Request(url, headers={"User-Agent": "artex-tools-bundle/1"})
            with opener.open(req, timeout=60) as response:
                checked_url(response.url)
                data = read_limited(response)
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
                tmp = Path(stream.name)
                stream.write(data)
            os.replace(tmp, target)
            return data
        except HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise BundleError(f"download failed ({exc.code}): {url}") from exc
        except (URLError, TimeoutError) as exc:
            if attempt == 2:
                raise BundleError(f"download failed: {url}: {exc}") from exc
        time.sleep(2 ** attempt)
    raise BundleError(f"download failed: {url}")


def checksum_pin(spec: dict, fetch) -> str | None:
    checksum = spec.get("checksums")
    if not checksum:
        return spec.get("sha256")
    data = fetch(checksum["url"])
    check_hash(data, checksum)
    matches = []
    for line in data.decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip("*") == checksum["filename"]:
            matches.append(fields[0])
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{64}", matches[0]):
        raise BundleError(f"missing or ambiguous checksum: {checksum['filename']}")
    return matches[0]


class ArchiveMemberValidator:
    """Check each member before retaining metadata or reading its contents."""

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.total = 0

    def check(self, name: str, size: int, regular: bool, directory: bool) -> str:
        if len(self.seen) >= MAX_MEMBERS or size < 0:
            raise BundleError("invalid archive size/count")
        name = safe_path(name)
        if name in self.seen:
            raise BundleError(f"duplicate archive member: {name}")
        if not regular and not directory:
            raise BundleError(f"links and special archive members are forbidden: {name}")
        self.total += size
        if self.total > LIMIT:
            raise BundleError("uncompressed archive too large")
        self.seen.add(name)
        return name


def extract_selected(data: bytes, kind: str, wanted: set[str]) -> dict[str, bytes]:
    """Read selected regular files; never extract an archive to the filesystem."""
    if kind == "raw":
        if wanted != {""}:
            raise BundleError("raw input requires one unnamed member")
        return {"": data}
    if kind == "gz":
        if wanted != {""}:
            raise BundleError("gzip input requires one unnamed member")
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            return {"": read_limited(stream)}
    result = {}
    validator = ArchiveMemberValidator()

    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                mode = info.external_attr >> 16
                directory = info.is_dir()
                regular = stat.S_IFMT(mode) in (0, stat.S_IFREG) and not directory
                name = validator.check(info.filename, info.file_size, regular, directory)
                if name in wanted:
                    if not regular:
                        raise BundleError(f"expected regular file: {name}")
                    with archive.open(info) as stream:
                        result[name] = read_limited(stream)
    elif kind == "tar.gz":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for info in archive:
                name = validator.check(info.name, info.size, info.isfile() and not info.issparse(), info.isdir())
                if name in wanted:
                    if not info.isfile():
                        raise BundleError(f"expected ordinary file: {name}")
                    stream = archive.extractfile(info)
                    if stream is None:
                        raise BundleError(f"cannot read member: {name}")
                    with stream:
                        result[name] = read_limited(stream)
    else:
        raise BundleError(f"unsupported archive format: {kind}")
    if set(result) != wanted:
        raise BundleError(f"missing archive members: {sorted(wanted - set(result))}")
    return result


def check_format(data: bytes, kind: str | None) -> None:
    if not data:
        raise BundleError("empty bundled file")
    if kind == "elf-amd64":
        if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
            raise BundleError("expected Linux amd64 ELF")
    elif kind == "pe":
        if len(data) < 64 or data[:2] != b"MZ":
            raise BundleError("expected Windows PE")
        offset = struct.unpack_from("<I", data, 60)[0]
        if data[offset:offset + 4] != b"PE\0\0":
            raise BundleError("invalid PE header")
    elif kind == "script":
        if not data.startswith(b"#!"):
            raise BundleError("expected a script with shebang")
    elif kind not in (None, "text"):
        raise BundleError(f"unknown format check: {kind}")


def validate_lock(lock: dict, manifest: dict) -> None:
    if lock.get("schema") != 1 or lock.get("platform") != "linux/amd64":
        raise BundleError("unsupported lock schema/platform")
    entries = manifest["tools"]
    names = {e["name"] for e in entries}
    if len(names) != len(entries):
        raise BundleError("duplicate tool in runtime manifest")
    bundled = lock["bundled"]
    external = lock["external"]
    if set(bundled) & set(external) or set(bundled) | set(external) != names:
        raise BundleError("every runtime-manifest tool must be bundled OR explicitly external")
    for name, reason in external.items():
        if not reason.get("reason") or not reason.get("upstream"):
            raise BundleError(f"external tool lacks explanation: {name}")
    destinations = set()
    for spec in lock["downloads"]:
        checked_url(spec["url"])
        if spec.get("format") not in ("raw", "gz", "zip", "tar.gz"):
            raise BundleError("unsupported download format")
        if not spec.get("files"):
            raise BundleError("download with no selected files")
        for key, size in (("sha256", 64), ("git_blob_sha1", 40)):
            if spec.get(key) and not re.fullmatch(r"[0-9a-f]{%d}" % size, spec[key]):
                raise BundleError(f"invalid {key}")
        if spec.get("checksums"):
            checksums = spec["checksums"]
            checked_url(checksums["url"])
            if not re.fullmatch(r"[0-9a-f]{64}", checksums.get("sha256", "")):
                raise BundleError("checksum list must itself be SHA-256 pinned")
        pinned = spec.get("sha256") or spec.get("git_blob_sha1") or spec.get("checksums")
        for output in spec["files"]:
            destination = safe_path(output["path"])
            if destination.split("/")[0] in METADATA or destination in destinations:
                raise BundleError(f"reserved or duplicate destination: {destination}")
            destinations.add(destination)
            if spec["format"] in ("zip", "tar.gz"):
                safe_path(output["member"])
            if output.get("sha256") and not re.fullmatch(r"[0-9a-f]{64}", output["sha256"]):
                raise BundleError("invalid selected-file SHA-256")
            if not pinned and not re.fullmatch(r"[0-9a-f]{64}", output.get("sha256", "")):
                raise BundleError("input or EACH selected output must have a reviewed digest")
            if output.get("mode", "0644") not in ("0644", "0755"):
                raise BundleError("only 0644/0755 modes are allowed")
    for entry in entries:
        path = safe_path(entry["path"])
        if not path.startswith("tools/"):
            raise BundleError("runtime path must be relative to data/tools")
        path = path[len("tools/"):]
        present = path in destinations or any(p.startswith(path + "/") for p in destinations)
        if (entry["name"] in bundled) != present:
            raise BundleError(f"coverage mismatch: {entry['name']}")
    for name, info in bundled.items():
        if not info.get("version") or not info.get("upstream") or not info.get("license_files"):
            raise BundleError(f"missing version/source/license metadata: {name}")
        if not set(info["license_files"]).issubset(destinations):
            raise BundleError(f"missing license file for {name}")


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def build_files(lock: dict, manifest: dict, instructions: bytes, fetch) -> dict[str, tuple[bytes, int]]:
    validate_lock(lock, manifest)
    files, inputs = {}, []
    for spec in lock["downloads"]:
        print(f"Fetch {spec['url']}", flush=True)
        data = fetch(spec["url"])
        pin = checksum_pin(spec, fetch)
        check_hash(data, {**spec, "sha256": pin})
        selected = extract_selected(data, spec["format"], {f.get("member", "") for f in spec["files"]})
        for output in spec["files"]:
            contents = selected[output.get("member", "")]
            check_hash(contents, output)
            check_format(contents, output.get("check"))
            files[output["path"]] = (contents, int(output.get("mode", "0644"), 8))
        inputs.append({"url": spec["url"], "sha256": sha256(data), "pin": pin or spec.get("git_blob_sha1") or "selected-file-sha256"})
    actual_manifest = copy.deepcopy(manifest)
    actual_manifest["_comment"] = "Generated bundle manifest. Python venv tools remain external; see bundle.json and INSTALL.md. Directory contents are covered by SHA256SUMS."
    for entry in actual_manifest["tools"]:
        name = entry["name"]
        relative = entry["path"][len("tools/"):]
        # Old deployment hashes must NOT be reused for different releases or
        # environment-specific Python entry-point wrappers.
        entry["sha256"] = sha256(files[relative][0]) if relative in files else ""
        if name in lock["bundled"]:
            entry["version"] = lock["bundled"][name]["version"]
        else:
            entry["version"] = lock["external"][name].get("version", "")
    inventory = {name: {"sha256": sha256(data), "size": len(data), "mode": oct(mode)} for name, (data, mode) in sorted(files.items())}
    files["tools-manifest.json"] = (json_bytes(actual_manifest), 0o644)
    files["sources.lock.json"] = (json_bytes(lock), 0o644)
    files["INSTALL.md"] = (instructions, 0o644)
    files["bundle.json"] = (json_bytes({"schema": 1, "platform": lock["platform"], "bundled": lock["bundled"], "external": lock["external"], "inputs": inputs, "files": inventory}), 0o644)
    sums = "".join(f"{sha256(data)}  {name}\n" for name, (data, _) in sorted(files.items()))
    files["SHA256SUMS"] = (sums.encode(), 0o644)
    return files


def write_archive(files: dict[str, tuple[bytes, int]], output: Path, epoch: int = 0) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as stream:
        tmp = Path(stream.name)
    try:
        with tmp.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path, (data, mode) in sorted(files.items()):
                    info = tarfile.TarInfo("data/tools/" + safe_path(path))
                    info.size, info.mode, info.mtime = len(data), mode, epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
        os.replace(tmp, output)
    finally:
        tmp.unlink(missing_ok=True)


def verify_archive(path: Path) -> None:
    with path.open("rb") as stream:
        data = read_limited(stream)
    # Independent re-read catches missing metadata or accidental repackaging.
    # Python 3.12 caches parsed TarInfo objects, so enforce limits on this first
    # traversal before asking tarfile for another header or skipping a payload.
    validator = ArchiveMemberValidator()
    modes = {}
    prefix = "data/tools/"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for info in archive:
            name = validator.check(info.name, info.size, info.isfile() and not info.issparse(), info.isdir())
            if not name.startswith(prefix):
                raise BundleError("bundle contains paths outside data/tools")
            if not info.isfile():
                raise BundleError(f"expected ordinary file: {name}")
            modes[name] = info.mode
    wanted = set(modes)
    if not wanted:
        raise BundleError("bundle contains paths outside data/tools")
    files = extract_selected(data, "tar.gz", wanted)
    required = {prefix + name for name in METADATA}
    if not required.issubset(files):
        raise BundleError("bundle metadata missing")
    checksummed = set()
    for line in files[prefix + "SHA256SUMS"].decode().splitlines():
        digest, name = line.split("  ", 1)
        name = prefix + safe_path(name)
        if name in checksummed or name not in files or sha256(files[name]) != digest:
            raise BundleError(f"invalid bundle checksum: {name}")
        checksummed.add(name)
    if checksummed != set(files) - {prefix + "SHA256SUMS"}:
        raise BundleError("bundle contains unchecked files")
    manifest = json.loads(files[prefix + "tools-manifest.json"])
    lock = json.loads(files[prefix + "sources.lock.json"])
    validate_lock(lock, manifest)
    for spec in lock["downloads"]:
        for output in spec["files"]:
            contents = files[prefix + output["path"]]
            if modes[prefix + output["path"]] != int(output.get("mode", "0644"), 8):
                raise BundleError("bundle file mode mismatch")
            check_hash(contents, output)
            check_format(contents, output.get("check"))
    for entry in manifest["tools"]:
        if entry["sha256"]:
            check_hash(files["data/" + entry["path"]], entry)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=ROOT / "packaging/tools-sources.lock.json")
    parser.add_argument("--manifest", type=Path, default=ROOT / "packaging/tools-manifest.json")
    parser.add_argument("--output", type=Path, default=ROOT / "images/tools.tar.gz")
    parser.add_argument("--cache", type=Path, default=ROOT / ".cache/tools-bundle")
    parser.add_argument("--validate", action="store_true", help="validate lock/manifest without network")
    parser.add_argument("--verify", type=Path, help="verify an existing bundle without network")
    args = parser.parse_args()
    try:
        if args.verify:
            verify_archive(args.verify)
            print(f"Verified {args.verify}")
            return 0
        lock = json.loads(args.lock.read_text())
        manifest = json.loads(args.manifest.read_text())
        validate_lock(lock, manifest)
        if args.validate:
            print(f"Validated: {len(lock['bundled'])} bundled, {len(lock['external'])} explicitly external")
            return 0
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
        if epoch < 0:
            raise BundleError("SOURCE_DATE_EPOCH must be non-negative")
        files = build_files(lock, manifest, (ROOT / "packaging/TOOLS.md").read_bytes(), lambda url: download(url, args.cache))
        write_archive(files, args.output, epoch)
        verify_archive(args.output)
        with args.output.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        args.output.with_name(args.output.name + ".sha256").write_text(f"{digest}  {args.output.name}\n")
        print(f"Built {args.output}: sha256:{digest}")
        return 0
    except (BundleError, OSError, KeyError, TypeError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"tools bundle failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
