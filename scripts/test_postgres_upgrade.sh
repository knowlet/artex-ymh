#!/usr/bin/env bash
# Real Docker regression; every container and volume belongs to a disposable project.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v docker >/dev/null
docker compose version >/dev/null
command -v python3 >/dev/null

TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/artex-pg-upgrade.XXXXXXXX")"
suffix="${TEST_DIR##*.}"
project16="artex-pg-upgrade-${suffix,,}-16"
project17="artex-pg-upgrade-${suffix,,}-17"
image_alias="artex-pg-upgrade-test:${suffix,,}"
project_mount="artex-pg-upgrade-${suffix,,}-mount"
project_partial="artex-pg-upgrade-${suffix,,}-partial"
projects=("$project16" "$project17" "$project_mount" "$project_partial")

# Explicit files exclude the operator's default override; the forced volume name
# and project names make cleanup independent of any deployed ARTEX instance.
cat > "$TEST_DIR/compose.test.yml" <<'YAML'
services:
  postgres:
    restart: "no"
    healthcheck:
      interval: 1s
      timeout: 3s
      retries: 60
volumes:
  pgdata:
    name: ${COMPOSE_PROJECT_NAME}_pgdata
    external: false
YAML
export COMPOSE_FILE="$ROOT/docker-compose.yml:$TEST_DIR/compose.test.yml"
base_compose_files="$COMPOSE_FILE"
export COMPOSE_PATH_SEPARATOR=:
export COMPOSE_PROJECT_NAME="$project16"
export POSTGRES_USER=artex_upgrade_test
export POSTGRES_DB=artex_upgrade_test
export POSTGRES_PASSWORD=disposable_upgrade_test_password
# An explicit empty value takes precedence over an operator's .env while still
# exercising the Compose ${POSTGRES_IMAGE:-postgres:16-alpine} default.
export POSTGRES_IMAGE=

cleanup() {
  local status=$? project
  trap - EXIT INT TERM
  if (( status != 0 )); then
    for project in "${projects[@]}"; do
      COMPOSE_PROJECT_NAME="$project" docker compose logs --no-color --tail=80 postgres || true
    done
  fi
  for project in "${projects[@]}"; do
    COMPOSE_PROJECT_NAME="$project" docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  done
  docker image rm "$image_alias" >/dev/null 2>&1 || true
  rm -rf -- "$TEST_DIR"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
check_version() { bash "$ROOT/scripts/check_postgres_version.sh"; }
start_postgres() { docker compose up -d --no-deps --wait --wait-timeout 120 postgres; }
sql() {
  docker compose exec -T postgres psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v ON_ERROR_STOP=1 -Atc "$1"
}
apply_schema() {
  local label="$1"
  if ! docker compose exec -T postgres psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v ON_ERROR_STOP=1 -q -f - < "$ROOT/db/schema.sql" > "$TEST_DIR/schema-$label.log" 2>&1; then
    cat "$TEST_DIR/schema-$label.log"
    fail "schema.sql failed on $label"
  fi
}
assert_rows() {
  [[ "$(sql "SELECT payload FROM upgrade_guard_sentinel WHERE id = 1")" == 'PG16-data-must-survive' ]] \
    || fail 'sentinel row changed or disappeared'
  [[ "$(sql "SELECT count(*) FROM companies WHERE nkey = 'postgres-upgrade-regression'")" == 1 ]] \
    || fail 'application row changed or disappeared'
}
volume_read() {
  local volume="${COMPOSE_PROJECT_NAME}_pgdata"
  # Fail if the fixture does not exist instead of accidentally creating an empty one.
  docker volume inspect "$volume" >/dev/null
  docker run --rm --network none --read-only --entrypoint sh \
    --mount "type=volume,src=$volume,dst=/source,readonly" \
    postgres:16-alpine -euc "$1"
}
fingerprint() {
  volume_read 'set -o pipefail; cd /source; find . -type f -exec sha256sum {} \; | LC_ALL=C sort | sha256sum'
}
expect_rejection() {
  local label="$1" expected_first="${2:-16}" expected_second="${3:-17}"
  local before_id before_hash after_hash output
  before_id="$(docker compose ps --all --quiet postgres)"
  before_hash="$(fingerprint)"
  if check_version > "$TEST_DIR/$label.log" 2>&1; then
    cat "$TEST_DIR/$label.log"
    fail "$label: incompatible PostgreSQL configuration was accepted"
  fi
  cat "$TEST_DIR/$label.log"
  output="$(< "$TEST_DIR/$label.log")"
  [[ "$output" == *"$expected_first"* && "$output" == *"$expected_second"* ]] \
    || fail "$label: error omits the conflicting data/server configuration"
  [[ -z "$(docker compose ps --status running --quiet postgres)" ]] \
    || fail "$label: preflight started PostgreSQL"
  [[ "$(docker compose ps --all --quiet postgres)" == "$before_id" ]] \
    || fail "$label: preflight replaced the stopped database container"
  after_hash="$(fingerprint)"
  [[ "$before_hash" == "$after_hash" ]] || fail "$label: preflight changed the data volume"
}

printf '%s\n' '1. Fresh deployment defaults to PostgreSQL 16.'
configured_image="$(docker compose config --format json | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["services"]["postgres"]["image"])')"
[[ "$configured_image" == postgres:16-alpine ]] || fail "unsafe default image: $configured_image"
configured_pgdata="$(docker compose config --format json | python3 -c '
import json, sys
env = json.load(sys.stdin)["services"]["postgres"].get("environment", {})
if isinstance(env, dict):
    print(env.get("PGDATA", ""))
elif isinstance(env, list):
    vals = [item.split("=", 1)[1] for item in env if item.startswith("PGDATA=")]
    print(vals[-1] if vals else "")
else:
    print("")
')"
[[ "$configured_pgdata" == /var/lib/postgresql/data ]] \
  || fail "PGDATA is not on the named volume: ${configured_pgdata:-<unset>}"
check_version
start_postgres
[[ "$(sql 'SHOW server_version_num')" == 16???? ]] || fail 'fresh deployment did not start PG16'
apply_schema pg16-first
sql "CREATE TABLE upgrade_guard_sentinel (id integer PRIMARY KEY, payload text NOT NULL);
     INSERT INTO upgrade_guard_sentinel VALUES (1, 'PG16-data-must-survive');
     INSERT INTO companies (name, nkey) VALUES ('Upgrade regression', 'postgres-upgrade-regression');" >/dev/null
apply_schema pg16-repeat
assert_rows
docker compose stop postgres
[[ "$(volume_read 'cat /source/PG_VERSION')" == 16 ]] || fail 'fixture is not a PG16 cluster'

printf '%s\n' '2. A changed PGDATA cannot hide the existing cluster in the volume root.'
cat > "$TEST_DIR/compose.pgdata.yml" <<'YAML'
services:
  postgres:
    environment:
      PGDATA: /var/lib/postgresql/data/pgdata
YAML
export COMPOSE_FILE="$base_compose_files:$TEST_DIR/compose.pgdata.yml"
expect_rejection changed-pgdata 'Existing cluster found at /var/lib/postgresql/data' \
  'PGDATA is /var/lib/postgresql/data/pgdata'
export COMPOSE_FILE="$base_compose_files"

printf '%s\n' '3. PG17 against an existing PG16 cluster is rejected without changing files.'
export POSTGRES_IMAGE=postgres:17-alpine
expect_rejection pg16-to-pg17

printf '%s\n' '4. The actual server version is checked even with a custom image tag.'
docker image tag postgres:16-alpine "$image_alias"
export POSTGRES_IMAGE="$image_alias"
check_version

printf '%s\n' '5. Restoring the matching PG16 image preserves existing data and schema.'
export POSTGRES_IMAGE=postgres:16-alpine
check_version
start_postgres
apply_schema pg16-recovered
assert_rows
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc \
  > "$TEST_DIR/pg16.dump"
[[ -s "$TEST_DIR/pg16.dump" ]] || fail 'PG16 logical backup is empty'
docker compose stop postgres
pg16_hash="$(fingerprint)"

printf '%s\n' '6. An explicit logical upgrade uses a separate fresh PG17 volume.'
export COMPOSE_PROJECT_NAME="$project17"
export POSTGRES_IMAGE=postgres:17-alpine
check_version
start_postgres
[[ "$(sql 'SHOW server_version_num')" == 17???? ]] || fail 'explicit deployment did not start PG17'
docker compose exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  --exit-on-error --single-transaction < "$TEST_DIR/pg16.dump"
apply_schema pg17-first
apply_schema pg17-repeat
assert_rows
docker compose stop postgres
[[ "$(volume_read 'cat /source/PG_VERSION')" == 17 ]] || fail 'fixture is not a PG17 cluster'

printf '%s\n' '7. A real PG17 cluster cannot be accidentally switched back to PG16.'
export POSTGRES_IMAGE=postgres:16-alpine
expect_rejection pg17-to-pg16
export POSTGRES_IMAGE=postgres:17-alpine
check_version
start_postgres
assert_rows

export COMPOSE_PROJECT_NAME="$project16"
[[ "$(fingerprint)" == "$pg16_hash" ]] || fail 'logical upgrade changed the original PG16 volume'

printf '%s\n' '8. The PostgreSQL 18 default PGDATA is rejected outside the mounted volume.'
export COMPOSE_PROJECT_NAME="$project_mount"
export POSTGRES_IMAGE=
cat > "$TEST_DIR/compose.outside.yml" <<'YAML'
services:
  postgres:
    environment:
      PGDATA: /var/lib/postgresql/18/docker
YAML
export COMPOSE_FILE="$base_compose_files:$TEST_DIR/compose.outside.yml"
if check_version > "$TEST_DIR/outside.log" 2>&1; then
  cat "$TEST_DIR/outside.log"
  fail 'PGDATA outside the mounted volume was accepted'
fi
cat "$TEST_DIR/outside.log"
output="$(< "$TEST_DIR/outside.log")"
[[ "$output" == *'outside the mounted volume /var/lib/postgresql/data'* \
  && "$output" == *'/var/lib/postgresql/18/docker'* ]] \
  || fail 'outside-volume error omits the mount or PGDATA path'
[[ -z "$(docker compose ps --status running --quiet postgres)" ]] \
  || fail 'outside-volume preflight started PostgreSQL'
docker volume inspect "${project_mount}_pgdata" >/dev/null
[[ -z "$(volume_read 'ls -A /source')" ]] || fail 'outside-volume preflight wrote to the mounted volume'
export COMPOSE_FILE="$base_compose_files"

printf '%s\n' '9. A nonempty standard directory without PG_VERSION cannot be bypassed.'
export COMPOSE_PROJECT_NAME="$project_partial"
docker compose run --rm --no-deps --user 0 --entrypoint sh postgres -euc \
  'printf partial > /var/lib/postgresql/data/partial.dat'
partial_before="$(fingerprint)"
cat > "$TEST_DIR/compose.partial.yml" <<'YAML'
services:
  postgres:
    environment:
      PGDATA: /var/lib/postgresql/data/pgdata
YAML
export COMPOSE_FILE="$base_compose_files:$TEST_DIR/compose.partial.yml"
if check_version > "$TEST_DIR/partial.log" 2>&1; then
  cat "$TEST_DIR/partial.log"
  fail 'nonempty legacy directory was accepted'
fi
cat "$TEST_DIR/partial.log"
output="$(< "$TEST_DIR/partial.log")"
[[ "$output" == *'Nonempty data directory at /var/lib/postgresql/data has no PG_VERSION'* \
  && "$output" == *'PGDATA is /var/lib/postgresql/data/pgdata'* ]] \
  || fail 'nonempty legacy directory was not reported'
[[ -z "$(docker compose ps --status running --quiet postgres)" ]] \
  || fail 'partial-directory preflight started PostgreSQL'
[[ "$(fingerprint)" == "$partial_before" ]] || fail 'preflight changed the partial volume'
export COMPOSE_FILE="$base_compose_files"

printf '%s\n' 'PASS: fresh install, mounted PGDATA, legacy directory guard, both major mismatch directions, PG16 recovery, schema replay, and isolated PG16-to-PG17 restore.'
