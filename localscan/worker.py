#!/usr/bin/env python3
"""Bounded, offline, operator-authorized Go CycloneDX SBOM scanning.

This module never downloads anything. The host Python interpreter, bubblewrap,
prlimit, installation, DB receipt, and current OS account are trusted. This is
not a boundary against a malicious same-UID process or a compromised kernel.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

TOOLS = ("osv-scanner", "trivy")
MAX_INPUT = 8 << 20
MAX_OUTPUT = 16 << 20
MAX_DIAGNOSTICS = 1 << 20
MAX_DB = 4 << 30
MAX_DB_METADATA = 1 << 20
DB_CHUNK = 1 << 20
MAX_BINARY = 256 << 20
MAX_AGE = dt.timedelta(days=7)
LOCK_PATH = Path(__file__).with_name("sources.lock.json")
DB_FILES = {"osv-scanner": ("osv-scanner/Go/all.zip",),
            "trivy": ("db/trivy.db", "db/metadata.json")}


class ScanError(ValueError):
    pass


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ScanError("duplicate JSON key")
        value[key] = item
    return value


def document(data):
    try:
        return json.loads(data, object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ScanError("nonfinite JSON number")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ScanError("invalid JSON document: " + str(exc)) from exc


def read_file(path, limit):
    # O_NOFOLLOW also refuses a final-component symlink after validation.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ScanError("nonregular or oversized file: " + str(path))
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ScanError("file exceeds byte budget")
    return data


def root_dir(value):
    path = Path(value)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ScanError("directory must be absolute and normalized")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ScanError("symlink directory is forbidden")
    if not path.is_dir():
        raise ScanError("directory does not exist: " + str(path))
    return path


def child(root, relative):
    parts = relative.split("/")
    if any(p in ("", ".", "..") for p in parts) or "\\" in relative:
        raise ScanError("unsafe relative path")
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ScanError("symlink input is forbidden")
    return path


def timestamp(value):
    if not isinstance(value, str):
        raise ScanError("database time must be RFC3339")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScanError("invalid database time") from exc
    if result.utcoffset() is None:
        raise ScanError("database time needs a timezone")
    return result.astimezone(dt.timezone.utc)


def fresh(value, now):
    age = now - timestamp(value)
    if age < -dt.timedelta(minutes=5) or age > MAX_AGE:
        raise ScanError("database is stale or future-dated (maximum age: 7 days)")


def stream_database(path, limit, target=None):
    """Hash/copy a bounded regular DB in fixed-size blocks, not one huge buffer.

    A target is a new file inside the caller's private staging directory. Only
    bytes actually read are hashed. Changed/truncated inputs and partial writes
    fail; a failed copy never leaves a success-looking staged file behind.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    created = False
    try:
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                raise ScanError(f"database must be a nonempty regular file within {limit} bytes: {path} (size={before.st_size})")
            output = target.open("xb") if target is not None else contextlib.nullcontext()
            created = target is not None
            total, checksum = 0, hashlib.sha256()
            with output as destination:
                while True:
                    block = source.read(min(DB_CHUNK, limit - total + 1))
                    if not block:
                        break
                    total += len(block)
                    if total > limit:
                        raise ScanError("database exceeds byte budget while reading")
                    checksum.update(block)
                    if destination is not None and destination.write(block) != len(block):
                        raise ScanError("short database snapshot write")
                after = os.fstat(source.fileno())
                if total != before.st_size or (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
                    raise ScanError("database changed or was truncated during read")
                if destination is not None:
                    destination.flush()
                    os.fsync(destination.fileno())
        return {"sha256": checksum.hexdigest(), "size": total}
    except BaseException:
        if created:
            target.unlink(missing_ok=True)
        raise


def db_file_limit(name, remaining):
    return min(remaining, MAX_DB_METADATA) if name.endswith(".json") else remaining


def db_receipt(tool, root, source, retrieved_at):
    """Operator-attested preparation receipt, NOT signed upstream provenance."""
    root = root_dir(root)
    if not isinstance(source, str) or not source.strip() or len(source) > 1024:
        raise ScanError("a bounded, explicit database source description is required")
    fresh(retrieved_at, dt.datetime.now(dt.timezone.utc))
    files, total = {}, 0
    for name in DB_FILES[tool]:
        files[name] = stream_database(child(root, name), db_file_limit(name, MAX_DB - total))
        total += files[name]["size"]
    return {"schema": 1, "tool": tool, "source": source, "retrieved_at": retrieved_at,
            "provenance": "operator-attested; not signature-verified", "files": files}


def copy_db(tool, root, destination, now):
    root = root_dir(root)
    raw = read_file(child(root, "artex-db.json"), MAX_INPUT)
    receipt = document(raw)
    if not isinstance(receipt, dict) or receipt.get("schema") != 1 or receipt.get("tool") != tool:
        raise ScanError("database receipt schema/tool mismatch")
    fresh(receipt.get("retrieved_at"), now)
    if not isinstance(receipt.get("source"), str) or not receipt["source"].strip():
        raise ScanError("database source is missing")
    files = receipt.get("files")
    if not isinstance(files, dict) or set(files) != set(DB_FILES[tool]):
        raise ScanError("database receipt does not cover the required files exactly")
    total, staged = 0, []
    try:
        for name in DB_FILES[tool]:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            actual = stream_database(child(root, name), db_file_limit(name, MAX_DB - total), target)
            staged.append(target)
            total += actual["size"]
            if files[name] != actual:
                raise ScanError("database hash/size mismatch: " + name)
            if tool == "trivy" and name == "db/metadata.json":
                metadata = document(read_file(target, MAX_DB_METADATA))
                if not isinstance(metadata, dict) or metadata.get("Version") != 2:
                    raise ScanError("unsupported Trivy DB schema")
                fresh(metadata.get("UpdatedAt"), now)
    except BaseException:
        for path in staged:
            path.unlink(missing_ok=True)
        raise
    return {"manifest_sha256": digest(raw), "source": receipt["source"],
            "retrieved_at": receipt["retrieved_at"], "files": files,
            "provenance": "operator-attested; not signature-verified"}


def static_elf(data):
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
        raise ScanError("expected Linux amd64 ELF")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if not 1 <= count <= 128 or size < 56 or offset + size * count > len(data):
        raise ScanError("invalid ELF program headers")
    for index in range(count):
        if struct.unpack_from("<I", data, offset + index * size)[0] == 3:
            raise ScanError("dynamic executables are unsupported by the minimal sandbox")


def verified_binary(tool, installation):
    root = root_dir(installation)
    lock = document(LOCK_PATH.read_bytes())
    if document(read_file(child(root, "sources.lock.json"), MAX_INPUT)) != lock:
        raise ScanError("installation source lock differs from the reviewed runtime lock")
    manifest = document(read_file(child(root, "tools-manifest.json"), MAX_INPUT))
    entries = manifest.get("tools")
    if not isinstance(entries, list) or sorted(e.get("name", "") for e in entries) != sorted(TOOLS):
        raise ScanError("installation inventory mismatch")
    entry = next(e for e in entries if e["name"] == tool)
    spec = lock["bundled"][tool]
    if entry.get("path") != "tools/" + tool or entry.get("version") != spec["version"]:
        raise ScanError("installation tool/version mismatch")
    # Installation is a trusted local store; detect accidental mutation. A
    # same-UID adversary can rewrite both manifest and executable (not covered).
    for path in (root, child(root, tool), child(root, "tools-manifest.json"), child(root, "sources.lock.json")):
        if path.stat().st_mode & 0o022:
            raise ScanError("installation must not be group/world writable")
    binary = read_file(child(root, tool), MAX_BINARY)
    if digest(binary) != entry.get("sha256"):
        raise ScanError("installed binary hash mismatch")
    static_elf(binary)
    for license_path in spec["license_files"]:
        notice = read_file(child(root, license_path), 128 << 10)
        source = next(d for d in lock["downloads"] if d["files"][0]["path"] == license_path)
        blob = hashlib.sha1(b"blob " + str(len(notice)).encode() + b"\0" + notice).hexdigest()
        if blob != source["git_blob_sha1"] or b"Apache License" not in notice:
            raise ScanError("license identity mismatch")
    return binary, spec


def version_key(value):
    if not isinstance(value, str) or not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?", value):
        raise ScanError("unsupported Go module version")
    return value.removeprefix("v")


def input_sbom(path):
    raw = read_file(path, MAX_INPUT)
    bom = document(raw)
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") not in ("1.4", "1.5", "1.6"):
        raise ScanError("requires a CycloneDX JSON 1.4-1.6 SBOM")
    components = bom.get("components")
    if not isinstance(components, list) or not 1 <= len(components) <= 5000:
        raise ScanError("requires 1-5000 explicit Go library components")
    canonical, packages = [], set()
    for component in components:
        if not isinstance(component, dict) or component.get("type") != "library" or component.get("components"):
            raise ScanError("only flat library components are supported")
        purl = component.get("purl", "")
        match = re.fullmatch(r"pkg:golang/([A-Za-z0-9._~!/-]+)@([^?#\s]+)", purl)
        if not match or any(p in ("", ".", "..") for p in match[1].split("/")):
            raise ScanError("only canonical Go package URLs without qualifiers are supported")
        name, version = match[1], version_key(match[2])
        if component.get("name") != name or version_key(component.get("version")) != version:
            raise ScanError("SBOM name/version and package URL disagree")
        if (name, version) in packages:
            raise ScanError("duplicate package identity")
        packages.add((name, version))
        canonical.append({"type": "library", "name": name, "version": version,
                          "purl": "pkg:golang/" + name + "@" + version})
    # No VEX, external references, config, commands, or remote URLs survive.
    staged = encoded({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                      "components": sorted(canonical, key=lambda item: item["purl"])})
    return raw, staged, packages


def tool_args(tool):
    if tool == "osv-scanner":
        return ["scan", "source", "--offline", "--format", "json", "--all-packages", "--sbom", "/input/bom.json"]
    if tool == "trivy":
        return ["sbom", "--scanners", "vuln", "--format", "json", "--list-all-pkgs",
                "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-version-check",
                "--cache-dir", "/db", "--cache-backend", "memory", "--disable-telemetry", "--exit-code", "0", "/input/bom.json"]
    raise ScanError("unsupported tool")


def parse_results(tool, data, exit_code, expected):
    native = document(data)
    if not isinstance(native, dict):
        raise ScanError("scanner output must be a JSON object")
    covered, findings = set(), []

    def identity(name, version):
        key = (name, version_key(version))
        if key not in expected:
            raise ScanError("scanner returned a package outside the input")
        covered.add(key)
        return key

    def finding(key, advisory, aliases, fixed, severity):
        if not isinstance(advisory, str) or not advisory or len(advisory) > 256:
            raise ScanError("missing or invalid advisory ID")
        if not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases):
            raise ScanError("invalid advisory aliases")
        findings.append({"package": key[0], "version": key[1], "ecosystem": "Go",
                         "advisory_id": advisory, "aliases": sorted(set(aliases)),
                         "fixed_versions": sorted(set(fixed)),
                         "severity": severity if isinstance(severity, str) else "UNKNOWN",
                         "validation": "database-match; exploitability-unverified"})

    if tool == "osv-scanner":
        if exit_code not in (0, 1) or not isinstance(native.get("results"), list):
            raise ScanError("OSV process or output schema failed")
        for result in native["results"]:
            if not isinstance(result, dict) or not isinstance(result.get("packages"), list):
                raise ScanError("missing OSV package inventory")
            for item in result["packages"]:
                package = item["package"]
                if package.get("ecosystem") != "Go":
                    raise ScanError("unexpected OSV ecosystem")
                key = identity(package["name"], package["version"])
                vulnerabilities = item.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    raise ScanError("invalid OSV vulnerabilities")
                for vuln in vulnerabilities:
                    fixed = []
                    for affected in vuln.get("affected", []):
                        if affected.get("package", {}).get("name") == key[0] and affected.get("package", {}).get("ecosystem") == "Go":
                            for item_range in affected.get("ranges", []):
                                for event in item_range.get("events", []):
                                    if isinstance(event.get("fixed"), str):
                                        fixed.append(event["fixed"])
                    finding(key, vuln["id"], vuln.get("aliases", []), fixed,
                            vuln.get("database_specific", {}).get("severity", "UNKNOWN"))
        if bool(findings) != (exit_code == 1):
            raise ScanError("OSV findings and exit code disagree")
    elif tool == "trivy":
        if exit_code != 0 or native.get("SchemaVersion") != 2 or not isinstance(native.get("Results"), list):
            raise ScanError("Trivy process or output schema failed")
        for result in native["Results"]:
            if result.get("Type") != "gomod" or not isinstance(result.get("Packages"), list):
                raise ScanError("missing or unsupported Trivy package inventory")
            for package in result["Packages"]:
                identity(package["Name"], package["Version"])
            for vuln in result.get("Vulnerabilities", []) or []:
                key = identity(vuln["PkgName"], vuln["InstalledVersion"])
                fixed = [v.strip() for v in (vuln.get("FixedVersion") or "").split(",") if v.strip()]
                finding(key, vuln["VulnerabilityID"], [], fixed, vuln.get("Severity", "UNKNOWN"))
    else:
        raise ScanError("unsupported tool")
    if covered != expected:
        raise ScanError("incomplete scanner coverage; absence of findings is not a clean scan")
    # Preserve separate upstream advisory IDs/aliases; do not call this a CVE count.
    unique = {json.dumps(f, sort_keys=True): f for f in findings}
    return sorted(unique.values(), key=lambda f: (f["package"], f["version"], f["advisory_id"]))


def sandbox_command(stage):
    return ["/usr/bin/prlimit", "--as=8589934592", "--cpu=120", "--fsize=67108864", "--nofile=128", "--",
            "/usr/bin/bwrap", "--unshare-all", "--new-session", "--die-with-parent", "--cap-drop", "ALL",
            "--ro-bind", str(stage / "scanner"), "/scanner",
            "--ro-bind", str(stage / "input"), "/input",
            "--ro-bind", str(stage / "db"), "/db",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/home",
            "--chdir", "/tmp", "--clearenv", "--setenv", "HOME", "/home",
            "--setenv", "TMPDIR", "/tmp", "--setenv", "GOMAXPROCS", "2",
            "--setenv", "GOMEMLIMIT", "768MiB", "--setenv", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "/db",
            "--", "/scanner"]


def bounded_process(argv, timeout):
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                            cwd="/", start_new_session=True)
    streams = selectors.DefaultSelector()
    buffers = [bytearray(), bytearray()]
    streams.register(proc.stdout, selectors.EVENT_READ, 0)
    streams.register(proc.stderr, selectors.EVENT_READ, 1)
    deadline = time.monotonic() + timeout
    error = None
    try:
        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ScanError("scanner wall-clock timeout")
            for event, _ in streams.select(min(remaining, 0.2)):
                block = os.read(event.fileobj.fileno(), 65536)
                if not block:
                    streams.unregister(event.fileobj)
                    continue
                index = event.data
                limit = (MAX_OUTPUT, MAX_DIAGNOSTICS)[index]
                if len(buffers[index]) + len(block) > limit:
                    raise ScanError("scanner output exceeded byte limit")
                buffers[index].extend(block)
        code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
    except (BaseException,) as exc:
        error = exc
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        code = proc.returncode
    finally:
        streams.close()
        proc.stdout.close()
        proc.stderr.close()
    return code, bytes(buffers[0]), bytes(buffers[1]), error


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def execute(options):
    if options.action == "run" and not options.authorized:
        raise ScanError("run requires --authorized for this local artifact")
    if not 1 <= options.timeout <= 300:
        raise ScanError("timeout must be between 1 and 300 seconds")
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ScanError("managed execution supports Linux amd64 only")
    binary, spec = verified_binary(options.tool, options.install_dir)
    raw, staged, packages = input_sbom(options.sbom)
    with tempfile.TemporaryDirectory(prefix="artex-local-scan-") as temporary:
        stage = Path(temporary)
        (stage / "input").mkdir()
        (stage / "db").mkdir()
        (stage / "input/bom.json").write_bytes(staged)
        (stage / "scanner").write_bytes(binary)
        (stage / "scanner").chmod(0o500)
        db = copy_db(options.tool, options.db_dir, stage / "db", dt.datetime.now(dt.timezone.utc))
        plan = {"schema": 1, "tool": options.tool, "version": spec["version"], "source_commit": spec["commit"],
                "binary_sha256": digest(binary), "input_sha256": digest(raw), "canonical_input_sha256": digest(staged),
                "database": db, "args": tool_args(options.tool), "packages": len(packages),
                "coverage_scope": "explicit Go CycloneDX library components only",
                "network": "new network namespace; no host networking; no fallback",
                "limits": {"wall_seconds": options.timeout, "cpu_seconds": 120, "address_space_bytes": 8 << 30,
                           "stdout_bytes": MAX_OUTPUT, "stderr_bytes": MAX_DIAGNOSTICS, "file_bytes": 64 << 20,
                           "database_bytes": MAX_DB, "database_copy_chunk_bytes": DB_CHUNK},
                "limitations": ["GOMEMLIMIT is a soft heap target, not a hard RSS limit",
                                "No aggregate scratch-space, multi-run concurrency, or host-wide resource quota",
                                "No protection against a malicious same-UID process or compromised sandbox/kernel",
                                "Database provenance is operator-attested, not signature-verified"]}
        if options.action == "plan":
            return plan
        for helper in ("/usr/bin/prlimit", "/usr/bin/bwrap"):
            if not os.path.isfile(helper) or not os.access(helper, os.X_OK):
                raise ScanError("required sandbox helper unavailable: " + helper)
        report = Path(options.report_dir)
        if not report.is_absolute():
            raise ScanError("report directory must be absolute")
        report.mkdir(mode=0o700)  # no existing output may be overwritten
        atomic_json(report / "result.json", {"schema": 1, "status": "running", "complete": False, "plan": plan})
        code, output, diagnostics, error = bounded_process(sandbox_command(stage) + tool_args(options.tool), options.timeout)
        (report / "native.json").write_bytes(output)
        (report / "stderr.txt").write_bytes(diagnostics)
        result = {"schema": 1, "status": "failed", "complete": False, "plan": plan,
                  "native_exit_code": code, "native_sha256": digest(output), "findings": []}
        try:
            if error is not None:
                raise ScanError(str(error) or "scanner interrupted")
            result["findings"] = parse_results(options.tool, output, code, packages)
            result.update(status="findings" if result["findings"] else "no_findings", complete=True)
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
            result["error"] = str(exc)
        atomic_json(report / "result.json", result)
        return result


def main(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("plan", "run"):
        command = commands.add_parser(action)
        command.add_argument("--tool", choices=TOOLS, required=True)
        command.add_argument("--install-dir", required=True)
        command.add_argument("--sbom", required=True)
        command.add_argument("--db-dir", required=True)
        command.add_argument("--timeout", type=int, default=120)
        if action == "run":
            command.add_argument("--authorized", action="store_true")
            command.add_argument("--report-dir", required=True)
    seal = commands.add_parser("seal-db", help="attest prepared database bytes; never download")
    seal.add_argument("--tool", choices=TOOLS, required=True)
    seal.add_argument("--db-dir", required=True)
    seal.add_argument("--source", required=True)
    seal.add_argument("--retrieved-at", required=True)
    options = parser.parse_args(args)
    try:
        if options.action == "seal-db":
            receipt = db_receipt(options.tool, options.db_dir, options.source, options.retrieved_at)
            path = root_dir(options.db_dir) / "artex-db.json"
            with path.open("xb") as stream:
                stream.write(encoded(receipt))
                stream.flush()
                os.fsync(stream.fileno())
            result = receipt
        else:
            result = execute(options)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, KeyboardInterrupt) as exc:
        result = {"schema": 1, "status": "failed", "complete": False, "findings": [], "error": str(exc)}
    sys.stdout.buffer.write(encoded(result))
    return 2 if result.get("status") == "failed" else (1 if result.get("status") == "findings" else 0)


if __name__ == "__main__":
    # SIGTERM must unwind the child process group, not orphan a scan.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt("cancelled")))
    raise SystemExit(main())
