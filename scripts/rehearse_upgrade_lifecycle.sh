#!/usr/bin/env bash
# Disposable PG rehearsal: seed → run app → dump → legacy strip → upgrade → restore → abort.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
EVIDENCE="${EVIDENCE_DIR:-$ROOT/packaging/upgrades/evidence}"
mkdir -p "$EVIDENCE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$EVIDENCE/lifecycle-$STAMP.log"
exec > >(tee -a "$LOG") 2>&1

PG_URL="${REHEARSE_PG_URL:?set REHEARSE_PG_URL to disposable DSN}"
BIN="${REHEARSE_ARTEX_BIN:-$ROOT/packaging/upgrades/evidence/artex-smoke}"
DATA_DIR="${REHEARSE_DATA_DIR:-/tmp/artex-rehearse-$STAMP}"
export ARTEX_PG_DSN="$PG_URL"
export ARTEX_DATA_DIR="$DATA_DIR"
export ARTEX_BIND_IP=127.0.0.1

if [[ ! -x "$BIN" ]]; then
  echo "Missing server binary $BIN (build with embed UI first)"
  exit 1
fi

mkdir -p "$DATA_DIR"
psql "$PG_URL" -v ON_ERROR_STOP=1 -c 'SELECT current_database(), version()'

echo "=== 1) Fresh schema via server bootstrap ==="
"$BIN" -addr 127.0.0.1:9877 >/tmp/artex-rehearse-boot.log 2>&1 &
PID=$!
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:9877/api/health >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -sf http://127.0.0.1:9877/api/health | tee "$EVIDENCE/health-$STAMP.json"

echo "=== 2) Seed auth + representative rows ==="
INIT_PW="rehearse-$STAMP"
curl -sf -X POST http://127.0.0.1:9877/api/auth/init \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"$INIT_PW\"}" | tee "$EVIDENCE/auth-init-$STAMP.json"
TOKEN=$(curl -sf -X POST http://127.0.0.1:9877/api/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"ARTEX\",\"password\":\"$INIT_PW\"}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))")
test -n "$TOKEN"
psql "$PG_URL" -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO companies (name, nkey) VALUES ('rehearse-co', 'rehearse-co-key')
ON CONFLICT (nkey) DO NOTHING;
SQL
ROWS=$(psql "$PG_URL" -At -c "SELECT count(*) FROM companies WHERE nkey='rehearse-co-key'")
test "$ROWS" = "1"

echo "=== 3) Logical backup (custom format) ==="
DUMP="$EVIDENCE/pre-upgrade-$STAMP.dump"
if [[ -n "${REHEARSE_PG_DOCKER:-}" ]]; then
  DB_NAME="$(psql "$PG_URL" -At -c 'SELECT current_database()')"
  sudo docker exec "$REHEARSE_PG_DOCKER" pg_dump -Fc -U artex_test -d "$DB_NAME" >"$DUMP"
else
  pg_dump -Fc "$PG_URL" -f "$DUMP"
fi
test -s "$DUMP"
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

echo "=== 4) Simulate prior-release llm_records (drop raw columns) ==="
psql "$PG_URL" -v ON_ERROR_STOP=1 -c \
  'ALTER TABLE IF EXISTS llm_records DROP COLUMN IF EXISTS raw_request, DROP COLUMN IF EXISTS raw_response'

echo "=== 5) Restart app — idempotent schema migration ==="
"$BIN" -addr 127.0.0.1:9877 >/tmp/artex-rehearse-upgrade.log 2>&1 &
PID=$!
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:9877/api/health >/dev/null 2>&1; then break; fi
  sleep 0.5
done
COLS=$(psql "$PG_URL" -At -c "SELECT count(*) FROM information_schema.columns WHERE table_name='llm_records' AND column_name IN ('raw_request','raw_response')")
test "$COLS" = "2"
ROWS_AFTER=$(psql "$PG_URL" -At -c "SELECT count(*) FROM companies WHERE nkey='rehearse-co-key'")
test "$ROWS_AFTER" = "1"
curl -sf -X POST http://127.0.0.1:9877/api/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"ARTEX\",\"password\":\"$INIT_PW\"}" >/dev/null

echo "=== 6) Rollback rehearsal: restore-only on fresh database ==="
RESTORE_URL="${REHEARSE_PG_RESTORE_URL:-}"
if [[ -z "$RESTORE_URL" ]]; then
  echo "REHEARSE_PG_RESTORE_URL not set; skipping restore DB step"
else
  if [[ -n "${REHEARSE_PG_DOCKER:-}" ]]; then
    RESTORE_DB="$(psql "$RESTORE_URL" -At -c 'SELECT current_database()')"
    sudo docker exec -i "$REHEARSE_PG_DOCKER" pg_restore --clean --if-exists -U artex_test -d "$RESTORE_DB" <"$DUMP"
  else
    pg_restore --clean --if-exists -d "$RESTORE_URL" "$DUMP"
  fi
  echo "Restored dump into isolated database (restore-only; downgrade binary not attempted)"
fi

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
echo "=== lifecycle rehearsal complete; log $LOG ==="
