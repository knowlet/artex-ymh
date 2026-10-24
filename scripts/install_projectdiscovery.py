#!/usr/bin/env python3
"""Stage a reviewed, hash-locked ProjectDiscovery Linux binary; never execute it.

The destination is DATA_DIR/tools/TOOL. This command can stage Linux artifacts
from another operating system. Expected release versions are metadata, not a
runtime version check. The verified archive's MIT notice is retained under
DATA_DIR/tools/licenses/TOOL before binary replacement. A later replacement
failure may leave that extra notice. Nuclei templates require separate review.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

TOOLS = ("httpx", "katana", "nuclei", "naabu", "subfinder")
PLATFORM = "linux/amd64"
MAX_LOCK_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_LICENSE_BYTES = 128 * 1024
LICENSE_NAMES = frozenset(("LICENSE", "LICENSE.md", "LICENSE.txt"))
OFFICIAL_DOWNLOAD_HOSTS = frozenset(
    ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
)


class InstallError(ValueError):
    """A validation or preparation failure, before replacing the binary."""


def bounded_read(stream, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise InstallError(f"input exceeds {limit} bytes")
    return data


def select_asset(lock: dict, tool: str) -> tuple[dict, dict]:
    if tool not in TOOLS or lock.get("schema_version") != 1:
        raise InstallError("unsupported tool or lock schema")
    entries = lock.get("tools")
    if not isinstance(entries, list) or any(not isinstance(x, dict) for x in entries):
        raise InstallError("invalid tools in lock")
    names = [x.get("name") for x in entries]
    if any(not isinstance(x, str) for x in names) or len(names) != len(set(names)):
        raise InstallError("invalid or duplicate tool names in lock")
    matches = [x for x in entries if x["name"] == tool]
    if len(matches) != 1:
        raise InstallError("tool missing from lock")
    entry = matches[0]
    version = entry.get("version", "")
    if not isinstance(version, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version):
        raise InstallError("invalid stable release version")
    if entry.get("repository") != f"projectdiscovery/{tool}":
        raise InstallError("unexpected repository")
    if not isinstance(entry.get("commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", entry["commit"]):
        raise InstallError("invalid source commit")
    expected_name = f"{tool}_{version[1:]}_linux_amd64.zip"
    assets = entry.get("assets")
    if not isinstance(assets, list) or any(not isinstance(x, dict) for x in assets):
        raise InstallError("invalid release assets")
    matching_assets = [x for x in assets if x.get("name") == expected_name]
    if len(matching_assets) != 1:
        raise InstallError("exact Linux amd64 ZIP asset missing or duplicated")
    asset = matching_assets[0]
    expected_url = f"https://github.com/projectdiscovery/{tool}/releases/download/{version}/{expected_name}"
    if asset.get("url") != expected_url:
        raise InstallError("unexpected release asset URL")
    if not isinstance(asset.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]):
        raise InstallError("missing release asset SHA-256")
    return entry, asset


def validate_download_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in OFFICIAL_DOWNLOAD_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise InstallError("download redirect is outside official HTTPS asset hosts")


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_download_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str) -> bytes:
    validate_download_url(url)
    opener = urllib.request.build_opener(OfficialRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "ARTEX-release-installer/1", "Accept": "application/octet-stream"})
    with opener.open(request, timeout=30) as response:
        validate_download_url(response.geturl())
        return bounded_read(response, MAX_ARCHIVE_BYTES)


def extract_payload(archive: bytes, tool: str) -> tuple[bytes, bytes]:
    """Validate ZIP metadata and return the root executable and MIT notice."""
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            members = bundle.infolist()
            if len(members) > 256:
                raise InstallError("too many archive entries")
            seen = set()
            executable = None
            licenses = []
            total = 0
            for member in members:
                name = member.filename
                path = PurePosixPath(name)
                if (
                    not name or len(name) > 1024 or "\\" in name
                    or path.is_absolute() or ".." in path.parts
                    or name in seen or member.orig_filename != name
                ):
                    raise InstallError("unsafe or duplicate archive path")
                seen.add(name)
                mode = member.external_attr >> 16
                kind = stat.S_IFMT(mode)
                allowed = (0, stat.S_IFDIR) if member.is_dir() else (0, stat.S_IFREG)
                if kind not in allowed:
                    raise InstallError("nonregular archive entry")
                if member.flag_bits & 1:
                    raise InstallError("encrypted archive entry")
                total += member.file_size
                if member.file_size > MAX_BINARY_BYTES or total > MAX_TOTAL_BYTES:
                    raise InstallError("archive uncompressed size exceeds limits")
                if name == tool and not member.is_dir():
                    executable = member
                if name in LICENSE_NAMES and not member.is_dir():
                    licenses.append(member)
            if executable is None or executable.file_size == 0:
                raise InstallError("root executable missing or empty")
            if len(licenses) != 1 or not 0 < licenses[0].file_size <= MAX_LICENSE_BYTES:
                raise InstallError("one nonempty root MIT license notice is required")
            with bundle.open(licenses[0]) as stream:
                license_bytes = bounded_read(stream, MAX_LICENSE_BYTES)
            try:
                notice = license_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise InstallError("license notice must be UTF-8") from exc
            if not all(part in notice for part in ("Copyright", "Permission is hereby granted, free of charge", "THE SOFTWARE IS PROVIDED")):
                raise InstallError("archive does not contain the expected MIT notice")
            with bundle.open(executable) as stream:
                binary = bounded_read(stream, MAX_BINARY_BYTES)
            if len(binary) != executable.file_size:
                raise InstallError("truncated executable")
            return binary, license_bytes
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
        raise InstallError(f"invalid ZIP archive: {exc}") from exc


def retain_license(tools_dir: Path, tool: str, archive_sha: str, notice: bytes) -> Path:
    """Publish a hash-named notice before dispatching the binary replacement.

    Notices are never overwritten or deleted. A later binary replacement error
    may leave this extra verified notice, while the old binary stays intact.
    """
    license_root = tools_dir / "licenses"
    license_dir = license_root / tool
    if license_root.is_symlink() or license_dir.is_symlink():
        raise InstallError("license directory must not be a symlink")
    license_dir.mkdir(parents=True, exist_ok=True)
    destination = license_dir / f"{archive_sha}.LICENSE.txt"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".license-", dir=license_dir, delete=False) as stage:
            temporary = Path(stage.name)
            stage.write(notice)
            stage.flush()
            os.fchmod(stage.fileno(), 0o644)
            os.fsync(stage.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError:
            if destination.is_symlink() or not destination.is_file():
                raise InstallError("existing license notice must be a regular file")
            with destination.open("rb") as stream:
                if bounded_read(stream, MAX_LICENSE_BYTES) != notice:
                    raise InstallError("existing license notice differs from verified archive")
        return destination
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def install(lock: dict, tool: str, data_dir: Path, archive: bytes) -> dict:
    entry, asset = select_asset(lock, tool)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise InstallError("archive exceeds compressed size limit")
    archive_sha = hashlib.sha256(archive).hexdigest()
    if archive_sha != asset["sha256"]:
        raise InstallError("release archive SHA-256 mismatch")
    binary, license_bytes = extract_payload(archive, tool)
    binary_sha = hashlib.sha256(binary).hexdigest()
    data_dir = Path(os.path.abspath(data_dir))
    tools_dir = data_dir / "tools"
    if data_dir.is_symlink() or tools_dir.is_symlink():
        raise InstallError("destination directory must not be a symlink")
    tools_dir.mkdir(parents=True, exist_ok=True)
    destination = tools_dir / tool
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise InstallError("existing destination must be a regular file")
    license_path = retain_license(tools_dir, tool, archive_sha, license_bytes)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=f".{tool}-", dir=tools_dir, delete=False) as stage:
            temporary = Path(stage.name)
            stage.write(binary)
            stage.flush()
            os.fchmod(stage.fileno(), 0o755)
            os.fsync(stage.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {
        "tool": tool, "platform": PLATFORM, "expected_version": entry["version"],
        "source_commit": entry["commit"], "archive_url": asset["url"],
        "archive_sha256": archive_sha, "installed_binary_sha256": binary_sha,
        "license": "MIT", "license_path": str(license_path),
        "license_sha256": hashlib.sha256(license_bytes).hexdigest(),
        "destination": str(destination), "installed": True,
        "runtime_version_verified": False, "scan_executed": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=TOOLS, required=True)
    parser.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[1] / "packaging/projectdiscovery-lock.json")
    parser.add_argument("--data-dir", type=Path, required=True, help="stage binary into DATA_DIR/tools/TOOL (replaces that file)")
    parser.add_argument("--platform", choices=[PLATFORM], default=PLATFORM, help="artifact target, independent of the current host; no binary is executed")
    parser.add_argument("--archive", type=Path, help="use a predownloaded ZIP instead of HTTPS; the same locked SHA-256 is required")
    args = parser.parse_args(argv)
    receipt = None
    try:
        with args.lock.open("rb") as stream:
            lock = json.loads(bounded_read(stream, MAX_LOCK_BYTES))
        if not isinstance(lock, dict):
            raise InstallError("lock must be an object")
        _, asset = select_asset(lock, args.tool)
        if args.archive is not None:
            with args.archive.open("rb") as stream:
                archive = bounded_read(stream, MAX_ARCHIVE_BYTES)
        else:
            archive = download(asset["url"])
        receipt = install(lock, args.tool, args.data_dir, archive)
        print(json.dumps(receipt, sort_keys=True))
        sys.stdout.flush()
        return 0
    except KeyboardInterrupt:
        print("installation interrupted; inspect destination if interruption occurred at commit", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        if receipt is not None:
            try:
                print(f"binary installed, but receipt output failed: {exc}", file=sys.stderr, flush=True)
            except (OSError, ValueError):
                pass
            return 3
        print(f"installation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    exit_code = main()
    if exit_code == 3:
        # Failed flushes can retain buffered output; Python's shutdown flush
        # would otherwise replace the committed-but-unreported exit 3 with 120.
        # Only the executable entrypoint owns these streams. main() leaves an
        # embedding caller's streams open, including when diagnostics fail.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
    raise SystemExit(exit_code)
