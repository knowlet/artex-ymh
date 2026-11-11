#!/usr/bin/env bash
# Security audits across Go + npm; exits non-zero when actionable findings affect shipped code.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE="${EVIDENCE_DIR:-$ROOT/packaging/upgrades/evidence}"
mkdir -p "$EVIDENCE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

cd "$ROOT"
GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.11}"
export GOTOOLCHAIN

if ! command -v govulncheck >/dev/null; then
  go install golang.org/x/vuln/cmd/govulncheck@latest
fi
export PATH="${HOME}/go/bin:${PATH}"

govulncheck ./... | tee "$EVIDENCE/govulncheck-$STAMP.txt"
if grep -q 'Your code is affected by [1-9]' "$EVIDENCE/govulncheck-$STAMP.txt"; then
  echo "govulncheck: actionable stdlib/module findings in executed code paths"
  exit 1
fi

(
  cd web
  npm audit --json >"$EVIDENCE/npm-audit-$STAMP.json"
  npm audit >"$EVIDENCE/npm-audit-$STAMP.txt" || true
)
python3 - <<'PY'
import json, pathlib, sys
path = sorted(pathlib.Path("packaging/upgrades/evidence").glob("npm-audit-*.json"))[-1]
data = json.loads(path.read_text())
v = data.get("metadata", {}).get("vulnerabilities", {})
high = v.get("high", 0) + v.get("critical", 0)
mod = v.get("moderate", 0)
# dev-only chain via shadcn/ts-morph; fail only on high/critical reachable in runtime deps
if high:
    print(f"npm audit: {high} high/critical", file=sys.stderr)
    sys.exit(1)
print(f"npm audit: moderate={mod} low={v.get('low',0)} (documented holds in matrix)")
PY

echo "Security audits complete → $EVIDENCE"
