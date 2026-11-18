#!/usr/bin/env bash
# Evidence: PG16 (pre-cutover) → pg_dump → PG17 restore → upgraded binary;
# rollback: same PRE-upgrade dump → fresh PG16 → baseline main binary.
# Does NOT attempt pg17 dump → pg16 (unsupported).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE="${EVIDENCE_DIR:-$ROOT/packaging/upgrades/evidence}"
mkdir -p "$EVIDENCE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
JSON="$EVIDENCE/pg-major-migration-${STAMP}.json"
LOG="$EVIDENCE/pg-major-migration-${STAMP}.log"
exec > >(tee -a "$LOG") 2>&1

: "${PG16_CONTAINER:=artex-pg16}"
: "${PG17_CONTAINER:=artex-pg17}"
: "${BASELINE_BIN:=${ROOT}/packaging/upgrades/evidence/artex-baseline-main}"
: "${UPGRADED_BIN:=${ROOT}/packaging/upgrades/evidence/artex-upgraded}"
PG16_PORT="${PG16_PORT:-5434}"
PG17_PORT="${PG17_PORT:-5433}"
PG_USER=artex_test
PG_PASS=disposable_test_password
BASE=/tmp/artex-pg-major-$STAMP
DATA_PRE="$BASE/data-pre"
DATA_POST="$BASE/data-post"
DATA_ROLL="$BASE/data-rollback"
mkdir -p "$DATA_PRE" "$DATA_POST" "$DATA_ROLL"

die() { echo "FATAL: $*" >&2; exit 1; }
[[ -x "$BASELINE_BIN" ]] || die "missing baseline binary $BASELINE_BIN (build from main)"
[[ -x "$UPGRADED_BIN" ]] || die "missing upgraded binary $UPGRADED_BIN"

wait_health() {
  local url=$1
  for _ in $(seq 1 80); do
    if curl -sf "$url/api/health" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  return 1
}

stop_pid() {
  local pid=$1
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

seed_marker() {
  local dir=$1
  echo "rehearse-stamp=$STAMP" >"$dir/migration-marker.txt"
  echo '{"rehearse":true}' >"$dir/config-snippet.json"
}

api_init_login() {
  local base=$1 pw=$2
  curl -sf -X POST "$base/api/auth/init" -H 'Content-Type: application/json' -d "{\"password\":\"$pw\"}" >/dev/null \
    || curl -sf -X POST "$base/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"ARTEX\",\"password\":\"$pw\"}" >/dev/null
  curl -sf -X POST "$base/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"ARTEX\",\"password\":\"$pw\"}"
}

echo "=== PG16→17 major rehearsal $STAMP ==="

for c in "$PG16_CONTAINER" "$PG17_CONTAINER"; do
  if ! sudo docker inspect "$c" >/dev/null 2>&1; then
    die "container $c missing; start postgres:16-alpine and postgres:17-alpine"
  fi
done

drop_create() {
  local port=$1 db=$2
  psql "postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${port}/postgres?sslmode=disable" -v ON_ERROR_STOP=1 \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${db}' AND pid <> pg_backend_pid();" \
    -c "DROP DATABASE IF EXISTS ${db};" -c "CREATE DATABASE ${db} OWNER ${PG_USER};"
}

PW="pg-major-$STAMP"
DB16=artex_pg16_pre
DB17=artex_pg17_upgraded
DB16RB=artex_pg16_rollback

drop_create "$PG16_PORT" "$DB16"
DSN16="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG16_PORT}/${DB16}?sslmode=disable"

echo "=== Phase A: baseline (main) binary on PG16 + seed ==="
seed_marker "$DATA_PRE"
ARTEX_PG_DSN="$DSN16" ARTEX_DATA_DIR="$DATA_PRE" ARTEX_BIND_IP=127.0.0.1 \
  "$BASELINE_BIN" -addr 127.0.0.1:9816 >/tmp/artex-pg16-base.log 2>&1 &
PID16=$!
wait_health "http://127.0.0.1:9816" || die "baseline failed to start"
TOKEN_JSON=$(api_init_login "http://127.0.0.1:9816" "$PW")
TOKEN=$(python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" <<<"$TOKEN_JSON")
[[ -n "$TOKEN" ]] || die "no token after init"

curl -sf -X POST "http://127.0.0.1:9816/api/task-categories" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"rehearse-category"}' >/dev/null
TASK_JSON=$(curl -sf -X POST "http://127.0.0.1:9816/api/tasks" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"rehearse-task","description":"pre-upgrade row","goal":"preserve through pg major"}')
TASK_ID=$(python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" <<<"$TASK_JSON")

psql "$DSN16" -v ON_ERROR_STOP=1 -c "INSERT INTO companies (name, nkey) VALUES ('pre-cutover-co','pre-cutover-co') ON CONFLICT DO NOTHING"
PRE_COMPANIES=$(psql "$DSN16" -At -c "SELECT count(*) FROM companies WHERE nkey='pre-cutover-co'")
PRE_TASKS=$(psql "$DSN16" -At -c "SELECT count(*) FROM tasks WHERE name='rehearse-task'")
stop_pid "$PID16"

echo "=== Phase B: PRE-upgrade backup (PG16 client) ==="
DUMP="$EVIDENCE/pg16-pre-cutover-${STAMP}.dump"
sudo docker exec "$PG16_CONTAINER" pg_dump -Fc -U "$PG_USER" -d "$DB16" >"$DUMP"
DUMP_SHA=$(sha256sum "$DUMP" | awk '{print $1}')
PG16_VER=$(psql "$DSN16" -At -c "SHOW server_version")

echo "=== Phase C: restore into fresh PG17 (supported upgrade path) ==="
drop_create "$PG17_PORT" "$DB17"
sudo docker exec -i "$PG17_CONTAINER" pg_restore --no-owner --role="$PG_USER" -U "$PG_USER" -d "$DB17" <"$DUMP"
PG17_VER=$(psql "postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG17_PORT}/${DB17}?sslmode=disable" -At -c "SHOW server_version")
DSN17="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG17_PORT}/${DB17}?sslmode=disable"

echo "=== Phase D: upgraded binary on PG17 ==="
cp -a "$DATA_PRE/." "$DATA_POST/"
echo "post-cutover-write=$(date -u +%s)" >>"$DATA_POST/migration-marker.txt"
ARTEX_PG_DSN="$DSN17" ARTEX_DATA_DIR="$DATA_POST" ARTEX_BIND_IP=127.0.0.1 \
  "$UPGRADED_BIN" -addr 127.0.0.1:9817 >/tmp/artex-pg17-up.log 2>&1 &
PID17=$!
wait_health "http://127.0.0.1:9817" || die "upgraded binary failed"
LOGIN17=$(curl -sf -X POST "http://127.0.0.1:9817/api/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"ARTEX\",\"password\":\"$PW\"}")
POST_COMPANIES=$(psql "$DSN17" -At -c "SELECT count(*) FROM companies WHERE nkey='pre-cutover-co'")
POST_TASKS=$(psql "$DSN17" -At -c "SELECT count(*) FROM tasks WHERE id='${TASK_ID}'")
POST_TASK_NAME=$(psql "$DSN17" -At -c "SELECT name FROM tasks WHERE id='${TASK_ID}'")
TASKS_API=$(curl -sf -H "Authorization: Bearer $(python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" <<<"$LOGIN17")" \
  "http://127.0.0.1:9817/api/tasks")
stop_pid "$PID17"

echo "=== Phase E: rollback — PRE-upgrade dump → fresh PG16 + baseline binary ==="
drop_create "$PG16_PORT" "$DB16RB"
sudo docker exec -i "$PG16_CONTAINER" pg_restore --no-owner --role="$PG_USER" -U "$PG_USER" -d "$DB16RB" <"$DUMP"
DSN16RB="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG16_PORT}/${DB16RB}?sslmode=disable"
seed_marker "$DATA_ROLL"
ARTEX_PG_DSN="$DSN16RB" ARTEX_DATA_DIR="$DATA_ROLL" ARTEX_BIND_IP=127.0.0.1 \
  "$BASELINE_BIN" -addr 127.0.0.1:9818 >/tmp/artex-pg16-rb.log 2>&1 &
PIDRB=$!
wait_health "http://127.0.0.1:9818" || die "rollback baseline failed"
RB_LOGIN=$(curl -sf -X POST "http://127.0.0.1:9818/api/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"ARTEX\",\"password\":\"$PW\"}")
RB_COMPANIES=$(psql "$DSN16RB" -At -c "SELECT count(*) FROM companies WHERE nkey='pre-cutover-co'")
RB_TASKS=$(psql "$DSN16RB" -At -c "SELECT count(*) FROM tasks WHERE name='rehearse-task'")
stop_pid "$PIDRB"

echo "=== Phase F: document unsupported PG17→PG16 dump (expect fail) ==="
UNSUPPORTED_NOTE="not_attempted"
if sudo docker exec "$PG17_CONTAINER" pg_dump -Fc -U "$PG_USER" -d "$DB17" >/tmp/pg17-only.dump 2>/dev/null; then
  set +e
  drop_create "$PG16_PORT" artex_pg16_from17attempt 2>/dev/null
  sudo docker exec -i "$PG16_CONTAINER" pg_restore -U "$PG_USER" -d artex_pg16_from17attempt < /tmp/pg17-only.dump 2>/tmp/pg17-restore16.err
  UNSUPPORTED_RC=$?
  UNSUPPORTED_NOTE=$(head -3 /tmp/pg17-restore16.err | tr '\n' ' ')
  set -e
fi

export REH_JSON="$JSON" REH_STAMP="$STAMP" REH_DUMP="$DUMP" REH_DUMP_SHA="$DUMP_SHA"
export REH_PG16_VER="$PG16_VER" REH_PG17_VER="$PG17_VER" REH_DB16="$DB16" REH_DB17="$DB17" REH_DB16RB="$DB16RB"
export REH_PRE_COMPANIES="$PRE_COMPANIES" REH_PRE_TASKS="$PRE_TASKS" REH_TASK_ID="$TASK_ID"
export REH_POST_COMPANIES="$POST_COMPANIES" REH_POST_TASKS="$POST_TASKS" REH_POST_TASK_NAME="$POST_TASK_NAME"
export REH_RB_COMPANIES="$RB_COMPANIES" REH_RB_TASKS="$RB_TASKS" REH_DATA_POST="$DATA_POST" REH_UNSUPPORTED="$UNSUPPORTED_NOTE"
export REH_AUTH_LOGIN_OK=$([[ -n "$LOGIN17" ]] && echo 1 || echo 0)
export REH_RB_LOGIN_OK=$([[ -n "$RB_LOGIN" ]] && echo 1 || echo 0)
python3 - <<'PY'
import json, os, pathlib
out = pathlib.Path(os.environ["REH_JSON"])
out.write_text(json.dumps({
  "schema": "artex-pg-major-rehearsal/v1",
  "timestamp_utc": os.environ["REH_STAMP"],
  "pre_cutover": {
    "postgres": os.environ["REH_PG16_VER"],
    "binary": "main baseline (go1.26.3 build)",
    "database": os.environ["REH_DB16"],
    "companies_seed": int(os.environ["REH_PRE_COMPANIES"]),
    "tasks_seed": int(os.environ["REH_PRE_TASKS"]),
    "task_id": os.environ["REH_TASK_ID"],
    "data_dir_marker": "migration-marker.txt",
  },
  "backup": {
    "tool": "pg_dump -Fc via PG16 container client",
    "file": pathlib.Path(os.environ["REH_DUMP"]).name,
    "sha256": os.environ["REH_DUMP_SHA"],
  },
  "cutover": {
    "method": "pg_restore into fresh PostgreSQL 17 database (logical dump/restore; pg_upgrade not used in this rehearsal)",
    "postgres": os.environ["REH_PG17_VER"],
    "database": os.environ["REH_DB17"],
  },
  "post_upgrade_verify": {
    "binary": "upgrade branch (go1.27.4)",
    "companies_preserved": int(os.environ["REH_POST_COMPANIES"]) == 1,
    "task_preserved": int(os.environ["REH_POST_TASKS"]) == 1 and os.environ["REH_POST_TASK_NAME"] == "rehearse-task",
    "auth_login": os.environ["REH_AUTH_LOGIN_OK"] == "1",
    "data_dir_pre_marker_survives": pathlib.Path(os.environ["REH_DATA_POST"], "migration-marker.txt").exists(),
    "post_cutover_data_loss_note": "Writes after cutover to PG17 (e.g. post-cutover-write line in data/) are NOT in the PG16-era dump; rollback restores DB to pre-cutover instant only — reconcile or lose post-cutover filesystem deltas.",
  },
  "rollback": {
    "method": "restore PRE-cutover PG16 dump into fresh PG16 database (NOT a PG17 dump)",
    "database": os.environ["REH_DB16RB"],
    "baseline_binary_smoke": os.environ["REH_RB_LOGIN_OK"] == "1",
    "companies_preserved": int(os.environ["REH_RB_COMPANIES"]) == 1,
    "tasks_preserved": int(os.environ["REH_RB_TASKS"]) == 1,
  },
  "unsupported": {
    "pg17_dump_restore_to_pg16": os.environ["REH_UNSUPPORTED"],
    "schema_major_downgrade": "restore-only via pre-cutover backup; never import PG17 logical dump into PG16",
  },
  "go_toolchain_note": "Go 1.26→1.27 is a compiler/runtime bump (redeploy prior binary); persistent irreversibility applies to PostgreSQL major state after cutover without a matching-era backup.",
}, indent=2) + "\n", encoding="utf-8")
print(out)
PY

test "$PRE_COMPANIES" = "1" && test "$POST_COMPANIES" = "1" && test "$RB_COMPANIES" = "1" || die "company seed mismatch"
test "$PRE_TASKS" = "1" && test "$POST_TASKS" = "1" && test "$RB_TASKS" = "1" || die "task seed mismatch"

echo "=== complete: $JSON ==="
