#!/usr/bin/env python3
"""Emit machine-readable dependency inventory for ARTEX upgrade audits."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], cwd: Path | None = None) -> str:
    return subprocess.check_output(cmd, cwd=cwd or ROOT, text=True, stderr=subprocess.STDOUT)


def go_direct_modules() -> list[dict]:
    locked: dict[str, str] = {}
    for line in run(["go", "list", "-m", "all"]).splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] != "github.com/Autumn-27/artex":
            locked[parts[0]] = parts[1]
    require_block = (ROOT / "go.mod").read_text()
    direct = re.findall(r"^\s+(\S+)\s+(\S+)", require_block.split("require (")[1].split("\n)")[0], re.M)
    out = [
        {
            "name": name,
            "version": locked.get(name, version),
            "indirect": False,
        }
        for name, version in direct
        if not version.endswith("// indirect")
    ]
    return sorted(out, key=lambda x: x["name"])


def npm_inventory() -> list[dict]:
    lock = json.loads((ROOT / "web/package-lock.json").read_text())
    pkg = json.loads((ROOT / "web/package.json").read_text())
    names = set(pkg.get("dependencies", {})) | set(pkg.get("devDependencies", {}))
    out = []
    for name in sorted(names):
        entry = lock["packages"].get(f"node_modules/{name}")
        if not entry:
            continue
        out.append({"name": name, "version": entry.get("version", "")})
    return out


def docker_base_images() -> list[dict]:
    dockerfiles = list(ROOT.glob("Dockerfile*"))
    images: list[dict] = []
    for path in dockerfiles:
        for line in path.read_text().splitlines():
            m = re.match(r"^FROM\s+(\S+)", line)
            if m:
                images.append({"file": path.name, "from": m.group(1)})
    return images


def github_actions_pins() -> list[dict]:
    pins: list[dict] = []
    for wf in (ROOT / ".github/workflows").glob("*.yml"):
        for line in wf.read_text().splitlines():
            m = re.match(r"\s*- uses: (\S+)", line)
            if m:
                pins.append({"workflow": wf.name, "uses": m.group(1)})
    return pins


def main() -> int:
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    inventory = {
        "schema": "artex-upgrade-inventory/v1",
        "generated_at": generated_at,
        "repo": "knowlet/artex-ymh",
        "reference_date": date.today().isoformat(),
        "toolchains": {
            "go": run(["go", "version"]).strip(),
            "node": run(["node", "-v"]).strip(),
            "npm": run(["npm", "-v"]).strip(),
        },
        "go_direct_modules": go_direct_modules(),
        "npm_packages": npm_inventory(),
        "docker_base_images": docker_base_images(),
        "github_actions_uses": github_actions_pins(),
        "ci_postgres_image": "postgres:17",
        "pr_integration_notes": {
            "pr15": "Adds intercept advisory Playwright e2e; no go.mod diff vs main at fetch time.",
            "pr17": "Audn URL validation; no dependency manifest diff vs main at fetch time.",
        },
    }
    out_dir = ROOT / "packaging" / "upgrades"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    path = out_dir / f"inventory-{stamp}.json"
    path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
