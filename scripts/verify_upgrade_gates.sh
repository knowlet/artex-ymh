#!/usr/bin/env bash
# Reproducible local/CI upgrade verification gates (disposable credentials only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT/packaging/upgrades/evidence}"
mkdir -p "$EVIDENCE_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$EVIDENCE_DIR/gates-$STAMP.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== ARTEX upgrade gates $STAMP ==="
echo "ROOT=$ROOT"
go version
node -v
npm -v

if [[ -z "${ARTEX_PG_DSN:-}" ]]; then
  echo "ARTEX_PG_DSN unset; PostgreSQL integration tests may skip."
else
  psql "$ARTEX_PG_DSN" -v ON_ERROR_STOP=1 -c 'SELECT 1'
  export ARTEX_AUTH_TEST_DSN="${ARTEX_AUTH_TEST_DSN:-$ARTEX_PG_DSN}"
fi

gofmt -l . | tee "$EVIDENCE_DIR/gofmt-dirty-$STAMP.txt"
test ! -s "$EVIDENCE_DIR/gofmt-dirty-$STAMP.txt"

go vet ./...

go test -count=1 -p=1 -timeout=15m ./... | tee "$EVIDENCE_DIR/go-test-$STAMP.txt"
go test -race -count=1 -p=1 -timeout=10m ./server ./mcphttp ./selfupdate ./traffic \
  -run '^(TestLogSink|TestUpdateAndRollback|TestUpdateRoutesReject|TestConcurrentRollbacks|TestSettlePreserves|TestNewSSEHandshake|TestLoginThrottle|TestSecurityPGConcurrent)' \
  | tee "$EVIDENCE_DIR/go-race-$STAMP.txt"

go build -tags embedui -o "$EVIDENCE_DIR/artex-$STAMP" ./cmd/artex

(
  cd web
  npm ci
  node --test src/lib/auth-refresh.test.mjs src/lib/safe-href.test.mjs
  npx tsc --noEmit
  npm run build:static
) | tee "$EVIDENCE_DIR/frontend-$STAMP.txt"

python3 scripts/collect_upgrade_inventory.py | tee "$EVIDENCE_DIR/inventory-path-$STAMP.txt"

echo "=== gates complete; log $LOG ==="
