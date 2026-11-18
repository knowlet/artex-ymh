#!/usr/bin/env bash
# Playwright e2e harness: disposable Postgres DB + embedui ARTEX on :8787.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
RUNTIME="$ROOT/web/e2e/.runtime"
DATA="$RUNTIME/data"
BIN="$RUNTIME/artex"
ARTEX_PG_DSN="${ARTEX_PG_DSN:-postgres://artex_test:disposable_test_password@localhost:5432/artex_e2e?sslmode=disable}"
E2E_PASSWORD="${E2E_PLAYWRIGHT_PASSWORD:-e2e-playwright-pass}"
export ARTEX_PG_DSN

mkdir -p "$RUNTIME" "$DATA"

if command -v psql >/dev/null 2>&1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -tc "SELECT 1 FROM pg_roles WHERE rolname='artex_test'" | grep -q 1 \
    || sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE USER artex_test WITH PASSWORD 'disposable_test_password';"
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS artex_e2e"
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE artex_e2e OWNER artex_test"
fi

if [[ ! -x "$BIN" ]] || [[ "${E2E_FORCE_BUILD:-}" == "1" ]]; then
  echo "[e2e] building frontend static export..."
  (cd "$ROOT/web" && npm run build:static)
  rm -rf "$ROOT/server/webui/dist"
  mkdir -p "$ROOT/server/webui/dist"
  cp -r "$ROOT/web/out/." "$ROOT/server/webui/dist/"
  echo "[e2e] building artex (-tags embedui)..."
  (cd "$ROOT" && CGO_ENABLED=0 go build -tags embedui -o "$BIN" ./cmd/artex)
fi

rm -rf "$DATA"
mkdir -p "$DATA"

cleanup() {
  if [[ -n "${ARTEX_PID:-}" ]]; then
    kill "$ARTEX_PID" 2>/dev/null || true
    wait "$ARTEX_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

"$BIN" -addr 127.0.0.1:8787 -data "$DATA" -proxy 127.0.0.1:8788 &
ARTEX_PID=$!

for _ in $(seq 1 120); do
  if curl -sf "http://127.0.0.1:8787/api/health" >/dev/null; then
    break
  fi
  sleep 1
done
if ! curl -sf "http://127.0.0.1:8787/api/health" >/dev/null; then
  echo "[e2e] backend failed to become healthy"
  exit 1
fi

curl -sf -X POST "http://127.0.0.1:8787/api/auth/init" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${E2E_PASSWORD}\"}" \
  | tee "$RUNTIME/auth-init.json" >/dev/null

TOKEN="$(python3 -c "import json; print(json.load(open('$RUNTIME/auth-init.json'))['token'])")"
printf '%s' "$TOKEN" >"$RUNTIME/access-token.txt"

psql "$ARTEX_PG_DSN" -v ON_ERROR_STOP=1 -f "$ROOT/web/e2e/bin/seed-e2e.sql"

TRAFFIC_DB="$DATA/traffic/_index/index.sqlite"
for _ in $(seq 1 60); do
  [[ -f "$TRAFFIC_DB" ]] && break
  sleep 1
done
if [[ -f "$TRAFFIC_DB" ]]; then
  sqlite3 "$TRAFFIC_DB" <<'SQL'
INSERT OR REPLACE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES ('e2e-ex-001', 1730000000, 'e2e.local', 'GET', '/e2e/vuln', 'http://e2e.local/e2e/vuln', 200, 'text/plain', 0, 10, '');
INSERT OR REPLACE INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body)
VALUES ('e2e-ex-001', 'GET /e2e/vuln HTTP/1.1', '', 'HTTP/1.1 200 OK', 'vulnerable');
SQL
fi

echo "[e2e] backend ready on :8787 (pid $ARTEX_PID)"
wait "$ARTEX_PID"
