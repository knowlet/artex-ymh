#!/usr/bin/env bash
# Browser E2E: disposable PostgreSQL + fake LLM provider + Next dev proxy. No paid models.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ARTEX_AUTH_TEST_DSN="${ARTEX_AUTH_TEST_DSN:-${ARTEX_PG_DSN:-}}"
if [[ -z "${ARTEX_AUTH_TEST_DSN}" ]]; then
  echo "ARTEX_AUTH_TEST_DSN or ARTEX_PG_DSN required" >&2
  exit 1
fi

export ARTEX_PG_DSN="$ARTEX_AUTH_TEST_DSN"
export ARTEX_E2E_SERVE=1
export ADVISORY_E2E_ADDR="${ADVISORY_E2E_ADDR:-127.0.0.1:9877}"
export ADVISORY_E2E_ENV_FILE="${ADVISORY_E2E_ENV_FILE:-$(mktemp /tmp/artex-advisory-e2e.XXXXXX.env)}"
export AUTOPENTEST_API="http://127.0.0.1:9877"
export ADVISORY_E2E_WEB_URL="${ADVISORY_E2E_WEB_URL:-http://127.0.0.1:3000}"

cleanup() {
  [[ -n "${BACKEND_PID:-}" ]] && kill "$BACKEND_PID" 2>/dev/null || true
  [[ -n "${WEB_PID:-}" ]] && kill "$WEB_PID" 2>/dev/null || true
  [[ -n "${ADVISORY_E2E_ENV_FILE:-}" && -f "${ADVISORY_E2E_ENV_FILE}" ]] && rm -f "${ADVISORY_E2E_ENV_FILE}"
  rm -f "$ROOT/server/jwt.key" 2>/dev/null || true
}
trap cleanup EXIT

cd "$ROOT"
go test ./server -run TestAdvisoryE2EServeForPlaywright -count=1 -timeout=30m &
BACKEND_PID=$!
for _ in $(seq 1 60); do
  [[ -f "$ADVISORY_E2E_ENV_FILE" ]] && break
  sleep 0.5
done
if [[ ! -f "$ADVISORY_E2E_ENV_FILE" ]]; then
  echo "backend e2e env file not created" >&2
  exit 1
fi

cd "$ROOT/web"
npm ci --ignore-scripts
npx playwright install chromium --with-deps 2>/dev/null || npx playwright install chromium
AUTOPENTEST_API="http://127.0.0.1:9877" npm run dev -- --hostname 127.0.0.1 --port 3000 &
WEB_PID=$!
for _ in $(seq 1 90); do
  curl -sf "http://127.0.0.1:3000/login" >/dev/null && break
  sleep 1
done

ADVISORY_E2E_ENV_FILE="$ADVISORY_E2E_ENV_FILE" ADVISORY_E2E_WEB_URL="$ADVISORY_E2E_WEB_URL" \
  npx playwright test -c playwright.advisory.config.ts --reporter=list
