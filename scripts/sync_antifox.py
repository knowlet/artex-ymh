#!/usr/bin/env python3
"""Build reviewed ARTEX adapters from a local, hash-pinned AntiFox snapshot.

No network, subprocesses, installers or runtime configuration changes. --write
creates missing files only; differing existing files require an explicit review.
"""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]


def read_pinned(path, digest, size=None):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"not a regular source file: {path}")
    data = path.read_bytes()
    if (size is not None and len(data) != size) or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"source identity mismatch: {path}")
    return data


def generated_files(root):
    provider = root / "providers/antifox"
    catalog = json.loads((provider / "catalog.json").read_text())
    snapshot = provider / "snapshot"
    license_spec = catalog["source"]["license"]
    license_data = read_pinned(snapshot / license_spec["path"], license_spec["sha256"])
    bridge = (provider / "bridge.md").read_text()
    report_bridge = (provider / "report-bridge.md").read_text()
    revision = catalog["source"]["revision"]
    repo = catalog["source"]["repository"]
    result = {}
    for entry in catalog["skills"]:
        original = read_pinned(snapshot / entry["source_path"], entry["source_sha256"], entry["source_bytes"])
        text = original.decode("utf-8")
        if not text.startswith("---\n") or "\n---\n" not in text:
            raise ValueError(f"frontmatter missing: {entry['id']}")
        body = text.split("\n---\n", 1)[1].lstrip("\n")
        name = f"{catalog['namespace']}-{entry['id']}"
        prefix = Path("skills") / name
        source_url = f"{repo}/blob/{revision}/{entry['source_path']}"
        frontmatter = "---\n" + f"name: {name}\ndescription: {json.dumps(entry['description'], ensure_ascii=False)}\nlicense: AGPL-3.0\n---\n\n"
        notice = f"改寫自 [AntiFox / {entry['id']}]({source_url})（AGPL-3.0）。原文與授權見 `${{SKILL_DIR}}/references/source.md`、`${{SKILL_DIR}}/references/LICENSE`。\n\n"
        if entry["id"] == "report-generation":
            body = report_bridge
        result[prefix / "SKILL.md"] = (frontmatter + notice + bridge.rstrip() + "\n\n" + body.rstrip() + "\n").encode()
        result[prefix / "references/source.md"] = original
        result[prefix / "references/LICENSE"] = license_data
    for resource in json.loads((provider / "resources.json").read_text()):
        data = read_pinned(snapshot / resource["source_path"], resource["sha256"], resource["bytes"])
        result[Path(resource["destination"])] = data
    return result


def sync(root, write=False):
    # Validate every source before publishing even one generated file.
    outputs = generated_files(root)
    mismatches = []
    missing = []
    for rel, data in outputs.items():
        target = root / rel
        if any(p.is_symlink() for p in [target, *target.parents] if p != root.parent):
            raise ValueError(f"symlink output refused: {rel}")
        if target.exists():
            if not target.is_file() or target.read_bytes() != data:
                mismatches.append(str(rel))
        else:
            missing.append((target, data))
    if mismatches:
        raise ValueError("refusing to overwrite existing edits: " + ", ".join(mismatches))
    if missing and not write:
        raise ValueError("missing generated files: " + ", ".join(str(p.relative_to(root)) for p, _ in missing))
    for target, data in missing:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(data)
    return len(outputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify source and adapter bytes (default)")
    mode.add_argument("--write", action="store_true", help="create missing adapters, refusing edits")
    args = parser.parse_args()
    try:
        count = sync(ROOT, write=args.write)
    except (OSError, ValueError, KeyError) as error:
        print(f"AntiFox bundle: {error}", file=sys.stderr)
        return 1
    print(f"AntiFox bundle verified: {count} files; no tools installed or executed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
