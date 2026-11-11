#!/usr/bin/env bash
# Security audits across Go + npm; records unreachable module advisories explicitly.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE="${EVIDENCE_DIR:-$ROOT/packaging/upgrades/evidence}"
mkdir -p "$EVIDENCE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

cd "$ROOT"
GOTOOLCHAIN="${GOTOOLCHAIN:-go1.27.4}"
export GOTOOLCHAIN

if ! command -v govulncheck >/dev/null; then
  go install golang.org/x/vuln/cmd/govulncheck@latest
fi
export PATH="${HOME}/go/bin:${PATH}"

govulncheck ./... | tee "$EVIDENCE/govulncheck-$STAMP.txt"
govulncheck -show verbose ./... >"$EVIDENCE/govulncheck-verbose-$STAMP.txt" 2>&1 || true
if grep -q 'Your code is affected by [1-9]' "$EVIDENCE/govulncheck-$STAMP.txt"; then
  echo "govulncheck: actionable stdlib/module findings in executed code paths"
  exit 1
fi

(
  cd web
  npm audit --json >"$EVIDENCE/npm-audit-$STAMP.json"
  npm audit >"$EVIDENCE/npm-audit-$STAMP.txt" 2>&1 || true
)
python3 - <<'PY'
import json, pathlib, sys
root = pathlib.Path("packaging/upgrades/evidence")
path = sorted(root.glob("npm-audit-*.json"))[-1]
data = json.loads(path.read_text())
meta = data.get("metadata", {}).get("vulnerabilities", {})
summary = {k: meta.get(k, 0) for k in ("info", "low", "moderate", "high", "critical", "total")}
report = root / f"npm-audit-summary-{path.stem.split('-', 2)[-1]}.json"
vulns = data.get("vulnerabilities") or {}
paths = [
    {
        "name": v.get("name"),
        "severity": v.get("severity"),
        "via": v.get("via"),
        "range": v.get("range"),
        "fixAvailable": v.get("fixAvailable"),
        "isDirect": v.get("isDirect"),
    }
    for v in vulns.values()
]
report.write_text(
    json.dumps({"summary": summary, "findings": paths}, indent=2) + "\n",
    encoding="utf-8",
)
print("npm severity counts:", summary)
for p in paths:
    print(f"  {p['severity']}: {p['name']} direct={p['isDirect']}")
high = summary.get("high", 0) + summary.get("critical", 0)
if high:
    sys.exit(1)
PY

echo "Security audits complete → $EVIDENCE"
