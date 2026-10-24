#!/usr/bin/env python3
"""Refresh metadata-only Nuclei CVE index from the templates release lock.

Explicit network invocation reads the official pinned cves.json JSONL and checks
the same-commit MIT notice against the retained local notice. No YAML request
templates, descriptions, payloads, or executables are imported or executed.
Offline --input is always local-unverified, with unverified licensing.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "packaging/nuclei-cve-index.json"
DEFAULT_LOCK = ROOT / "packaging/projectdiscovery-lock.json"
DEFAULT_LICENSE = ROOT / "packaging/discovery/NUCLEI-LICENSE.txt"
REPOSITORY = "projectdiscovery/nuclei-templates"
RAW_BASE = "https://raw.githubusercontent.com/" + REPOSITORY + "/"
MAX_BYTES = 16 * 1024 * 1024
MAX_LINE = 128 * 1024
MAX_ROWS = 50000
CVE_ID = re.compile(r"(CVE-[0-9]{4}-[0-9]{4,19})(?:-[A-Za-z0-9_-]+)?\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
PROTOCOLS = {"http", "network", "javascript"}


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("official-source redirect refused")


def download(url: str, limit: int = MAX_BYTES) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "raw.githubusercontent.com"
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("only the fixed official HTTPS raw source is permitted")
    suffix = parsed.path.removeprefix("/" + REPOSITORY + "/")
    commit, sep, filename = suffix.partition("/")
    if not sep or not SHA.fullmatch(commit) or filename not in {"cves.json", "LICENSE.md"}:
        raise ValueError("unexpected official source path")
    request = urllib.request.Request(url, headers={"User-Agent": "ARTEX-Nuclei-Index/1"})
    with urllib.request.build_opener(NoRedirects()).open(request, timeout=20) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("source exceeds size limit")
    return raw


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def decode(raw: bytes):
    try:
        return json.loads(raw, object_pairs_hook=unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON constant: " + value)))
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds decoder limit") from error


def nonempty(value, label: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(ch) < 32 for ch in value):
        raise ValueError("invalid " + label)
    return value


def template_path(value) -> str:
    path = nonempty(value, "template path", 512)
    parts = PurePosixPath(path).parts
    if (path.startswith("/") or "\\" in path or not re.fullmatch(r"[A-Za-z0-9_./-]+", path)
            or any(part in {".", ".."} for part in path.split("/"))
            or len(parts) < 4 or parts[0] not in PROTOCOLS or parts[1] != "cves"
            or not re.fullmatch(r"[0-9]{4}", parts[2]) or parts[-1].endswith((".yaml", ".yml")) is False
            or str(PurePosixPath(path)) != path):
        raise ValueError("template path must be a relative protocol/cves/year YAML path")
    return path


def normalize_rows(raw: bytes) -> list[dict]:
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("empty or oversized source")
    rows, seen_paths = [], set()
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        if len(line) > MAX_LINE or len(rows) >= MAX_ROWS:
            raise ValueError("JSONL row or entry count exceeds limit")
        row = decode(line)
        if not isinstance(row, dict) or not isinstance(row.get("Info"), dict):
            raise ValueError(f"invalid metadata row {number}")
        template_id = nonempty(row.get("ID"), "template ID", 160)
        matched = CVE_ID.fullmatch(template_id)
        if not matched:
            raise ValueError("template ID must begin with a complete CVE identifier")
        path = template_path(row.get("file_path"))
        if path in seen_paths:
            raise ValueError("duplicate template path: " + path)
        seen_paths.add(path)
        info = row["Info"]
        severity = info.get("Severity")
        if not isinstance(severity, str) or severity not in SEVERITIES:
            raise ValueError("invalid severity")
        normalized = {"cve_id": matched.group(1), "template_id": template_id,
                      "title": nonempty(info.get("Name"), "template title"),
                      "severity": severity, "path": path, "protocol": path.split("/", 1)[0]}
        classification = info.get("Classification")
        if not isinstance(classification, dict):
            raise ValueError("missing CVSS classification")
        score = classification.get("CVSSScore")
        if score != "N/A":
            if not isinstance(score, str) or not re.fullmatch(r"(?:[0-9](?:\.[0-9]+)?|10(?:\.0+)?)", score):
                raise ValueError("invalid CVSS score")
            normalized["cvss_score"] = float(score)
        rows.append(normalized)
    if not rows:
        raise ValueError("metadata index must be nonempty")
    return sorted(rows, key=lambda row: (row["cve_id"], row["template_id"], row["path"]))


def lock_source(lock: dict) -> dict:
    if not isinstance(lock, dict) or lock.get("schema_version") != 1 or not isinstance(lock.get("tools"), list):
        raise ValueError("unsupported release lock")
    entries = [entry for entry in lock["tools"] if isinstance(entry, dict) and entry.get("name") == "nuclei-templates"]
    if len(entries) != 1:
        raise ValueError("release lock needs exactly one templates entry")
    entry = entries[0]
    commit, release, published = entry.get("commit"), entry.get("version"), entry.get("release_published_at")
    if (entry.get("repository") != REPOSITORY or entry.get("license") != "MIT"
            or not isinstance(commit, str) or not SHA.fullmatch(commit)
            or not isinstance(release, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release)
            or entry.get("release_url") != "https://github.com/" + REPOSITORY + "/releases/tag/" + release):
        raise ValueError("release lock templates identity is invalid")
    if not isinstance(published, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", published):
        raise ValueError("invalid release publication timestamp")
    dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
    return {"kind": "official-github", "repository": REPOSITORY, "commit": commit,
            "url": RAW_BASE + commit + "/cves.json", "release": release,
            "release_published_at": published}


def verify_notice(raw: bytes) -> None:
    if not raw or len(raw) > 128 * 1024:
        raise ValueError("empty or oversized license notice")
    text = raw.decode("utf-8")
    if not (text.startswith("MIT License") and "Permission is hereby granted, free of charge" in text
            and "The above copyright notice and this permission notice shall be included" in text
            and 'THE SOFTWARE IS PROVIDED "AS IS"' in text):
        raise ValueError("upstream license requires manual review")


def snapshot(raw: bytes, source: dict | None = None) -> dict:
    rows = normalize_rows(raw)
    identity = {"kind": "local-unverified"} if source is None else dict(source)
    identity["sha256"] = hashlib.sha256(raw).hexdigest()
    if source is not None:
        identity["blob_sha"] = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    document = {"schema_version": 1, "source": identity,
                "license": "MIT" if source is not None else "unverified",
                "scope": "Nuclei CVE template metadata only; not the complete CVE List or a vulnerability finding.",
                "count": len(rows), "unique_cve_count": len({row["cve_id"] for row in rows}), "templates": rows}
    if source is not None:
        document["license_file"] = "discovery/NUCLEI-LICENSE.txt"
    validate_index(document)
    return document


def validate_index(document: dict) -> None:
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("unsupported metadata index schema")
    rows, source = document.get("templates"), document.get("source")
    if (not isinstance(rows, list) or not rows or len(rows) > MAX_ROWS
            or type(document.get("count")) is not int or document["count"] != len(rows)
            or not isinstance(source, dict) or not isinstance(source.get("sha256"), str)
            or not SHA256.fullmatch(source["sha256"])):
        raise ValueError("invalid metadata index count or source")
    if source.get("kind") == "official-github":
        expected = lock_source({"schema_version": 1, "tools": [{"name": "nuclei-templates", "repository": source.get("repository"),
            "license": "MIT", "commit": source.get("commit"), "version": source.get("release"),
            "release_published_at": source.get("release_published_at"),
            "release_url": "https://github.com/" + REPOSITORY + "/releases/tag/" + str(source.get("release"))}]})
        if (any(source.get(key) != value for key, value in expected.items())
                or not isinstance(source.get("blob_sha"), str) or not SHA.fullmatch(source["blob_sha"])
                or document.get("license") != "MIT" or document.get("license_file") != "discovery/NUCLEI-LICENSE.txt"):
            raise ValueError("invalid official metadata provenance")
    elif source.get("kind") != "local-unverified" or document.get("license") != "unverified" or set(source) != {"kind", "sha256"} or "license_file" in document:
        raise ValueError("invalid local metadata provenance")
    seen, cves = set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) - {"cve_id", "template_id", "title", "severity", "path", "protocol", "cvss_score"}:
            raise ValueError("metadata-only fields required")
        template_id = nonempty(row.get("template_id"), "template ID", 160)
        matched = CVE_ID.fullmatch(template_id)
        path = template_path(row.get("path"))
        if (not matched or row.get("cve_id") != matched.group(1) or path in seen
                or row.get("protocol") != path.split("/", 1)[0] or not isinstance(row.get("severity"), str)
                or row["severity"] not in SEVERITIES):
            raise ValueError("invalid or duplicate template metadata")
        nonempty(row.get("title"), "template title")
        if "cvss_score" in row:
            score = row["cvss_score"]
            if type(score) not in {int, float} or not math.isfinite(score) or not 0 <= score <= 10:
                raise ValueError("invalid normalized CVSS score")
        seen.add(path)
        cves.add(row["cve_id"])
    if type(document.get("unique_cve_count")) is not int or document["unique_cve_count"] != len(cves):
        raise ValueError("unique CVE count does not match metadata")


def encoded(document: dict) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def atomic_write(path: Path, raw: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def main(argv=None, fetch=download) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="offline JSONL; provenance and licensing remain unverified")
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--license", type=Path, default=DEFAULT_LICENSE, help="retained MIT notice to compare with official source")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="compare without writing; exit 2 on change")
    args = parser.parse_args(argv)
    if args.input is not None and args.lock != DEFAULT_LOCK:
        parser.error("--input cannot be combined with an alternate --lock")
    committed = False
    try:
        if args.input is not None:
            with args.input.open("rb") as stream:
                document = snapshot(stream.read(MAX_BYTES + 1))
        else:
            with args.lock.open("rb") as stream:
                lock_raw = stream.read(4 * 1024 * 1024 + 1)
            if len(lock_raw) > 4 * 1024 * 1024:
                raise ValueError("release lock exceeds size limit")
            source = lock_source(decode(lock_raw))
            notice = fetch(RAW_BASE + source["commit"] + "/LICENSE.md", 128 * 1024)
            verify_notice(notice)
            with args.license.open("rb") as stream:
                local_notice = stream.read(128 * 1024 + 1)
            if local_notice != notice:
                raise ValueError("retained MIT notice differs; review and update it before refreshing")
            document = snapshot(fetch(source["url"]), source)
        output = encoded(document)
        if args.check:
            try:
                with args.output.open("rb") as stream:
                    existing = stream.read(MAX_BYTES + 1)
                equal = decode(existing) == document
            except FileNotFoundError:
                equal = False
            print("current" if equal else "update available")
            return 0 if equal else 2
        atomic_write(args.output, output)
        committed = True
        print(f"saved {document['count']} template metadata rows for {document['unique_cve_count']} CVEs; no templates installed", flush=True)
        return 0
    except (ValueError, OSError, urllib.error.URLError) as error:
        print(("Nuclei metadata index committed, but reporting failed: " if committed else "Nuclei metadata index unchanged: ") + str(error), file=sys.stderr)
        return 3 if committed else 1


if __name__ == "__main__":
    exit_code = main()
    if exit_code == 3:
        # A failed buffered stdout flush must not make interpreter shutdown
        # replace the committed-output exit code with Python's exit 120.
        # Keep imported main() callers' streams untouched.
        try:
            sys.stdout.close()
        except OSError:
            pass
    raise SystemExit(exit_code)
