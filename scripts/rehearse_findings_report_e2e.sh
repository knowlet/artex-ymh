#!/usr/bin/env bash
# Disposable PG17 + real artex: seed findings, API byte assertions, Playwright UI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
EVIDENCE="$ROOT/packaging/upgrades/evidence"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$EVIDENCE/findings-report-e2e-$STAMP.log"
SEED_JSON="$EVIDENCE/findings-seed-$STAMP.json"
FIXTURE="$ROOT/packaging/upgrades/e2e/fixtures/upload-sample.txt"
export ARTEX_UPLOAD_FIXTURE="$FIXTURE"

PG_HOST="${ARTEX_PG_HOST:-127.0.0.1}"
PG_PORT="${ARTEX_PG_PORT:-5433}"
PG_USER="${ARTEX_PG_USER:-artex_test}"
PG_PASS="${ARTEX_PG_PASS:-disposable_test_password}"
DB="artex_findings_e2e_${STAMP}"
export ARTEX_PG_DSN="postgres://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/${DB}?sslmode=disable"

DATA_DIR="$EVIDENCE/data/findings-e2e-$STAMP"
BIN="${REHEARSE_ARTEX_BIN:-$EVIDENCE/artex-upgraded}"
ADDR="127.0.0.1:8787"
E2E_PASSWORD="${ARTEX_E2E_PASSWORD:-ui-e2e-disposable}"
export ARTEX_E2E_BASE_URL="http://${ADDR}"
export ARTEX_E2E_PASSWORD
export ARTEX_FINDINGS_SEED_PATH="$SEED_JSON"

mkdir -p "$DATA_DIR" "$EVIDENCE"
exec > >(tee -a "$LOG") 2>&1

echo "=== findings/report E2E $STAMP ==="
psql "postgres://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/postgres?sslmode=disable" -v ON_ERROR_STOP=1 \
  -c "DROP DATABASE IF EXISTS \"${DB}\";"
psql "postgres://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/postgres?sslmode=disable" -v ON_ERROR_STOP=1 \
  -c "CREATE DATABASE \"${DB}\";"

if [[ ! -x "$BIN" ]]; then
  echo "building artex binary → $BIN"
  go build -tags embedui -o "$BIN" ./cmd/artex
fi

export ARTEX_DATA_DIR="$DATA_DIR"
export ARTEX_BIND_IP=127.0.0.1
export ARTEX_GATE=off
export ARTEX_FINDINGS_SEED_OUT="$SEED_JSON"

echo "seeding disposable findings (PG only, before server start)"
go run ./packaging/upgrades/cmd/seed-disposable-findings | tee "$SEED_JSON"

ARTEX_PID=""
cleanup() {
  if [[ -n "$ARTEX_PID" ]] && kill -0 "$ARTEX_PID" 2>/dev/null; then
    kill "$ARTEX_PID" 2>/dev/null || true
    wait "$ARTEX_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

"$BIN" -addr "127.0.0.1:8787" &
ARTEX_PID=$!
for i in $(seq 1 60); do
  if curl -sf "http://${ADDR}/api/health" >/dev/null; then break; fi
  sleep 0.5
done
curl -sf "http://${ADDR}/api/health" >/dev/null

INIT=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://${ADDR}/api/auth/init" \
  -H 'Content-Type: application/json' -d "{\"password\":\"${E2E_PASSWORD}\"}")
if [[ "$INIT" != "200" && "$INIT" != "409" ]]; then
  echo "auth init failed: $INIT"
  exit 1
fi

(
  cd "$ROOT/packaging/upgrades/e2e"
  if [[ ! -d node_modules/@playwright/test ]]; then
    npm ci
    npx playwright install chromium
  fi
  npx playwright test findings-report-workflows.spec.ts ui-workflows.spec.ts workflows.spec.ts smoke.spec.ts
) | tee "$EVIDENCE/playwright-findings-report-$STAMP.log"

python3 - <<PY
import json, hashlib, pathlib
root = pathlib.Path("$ROOT")
evidence = root / "packaging/upgrades/evidence"
summary_path = evidence / "TEST-SUMMARY-2026-11-11.json"
summary = json.loads(summary_path.read_text())
seed = json.loads(pathlib.Path("$SEED_JSON").read_text())
fixture = pathlib.Path("$FIXTURE").read_bytes()
summary["findings_report_e2e"] = {
    "stamp": "$STAMP",
    "seed": seed,
    "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
    "artifact": pathlib.Path("$LOG").name,
    "playwright_log": f"playwright-findings-report-$STAMP.log",
    "pg_upgrade_note": "logical dump/restore only; pg_upgrade not supported in this pack",
}
summary_path.write_text(json.dumps(summary, indent=2) + "\\n")
print("updated", summary_path)
PY

echo "=== findings/report E2E complete; seed $SEED_JSON ==="
