#!/usr/bin/env bash
# Inspect the configured PostgreSQL binary and mounted cluster before deployment.
# The official entrypoint is bypassed: this never starts postgres or runs initdb.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"

command -v docker >/dev/null 2>&1 || {
  echo "PostgreSQL preflight requires Docker / Compose." >&2
  exit 1
}

# Compose resolves .env, COMPOSE_FILE/COMPOSE_PROJECT_NAME, image overrides and
# PGDATA exactly as it does for the real service. Do not infer a major from a tag
# or assume that the current directory determines the deployed volume name.
docker compose run --rm --no-deps -T --entrypoint sh postgres -ec '
  fail() {
    printf "PostgreSQL preflight: %s\n" "$*" >&2
    printf "Keep the existing data volume. See docs/POSTGRES-UPGRADE.md.\n" >&2
    exit 1
  }

  data_dir=${PGDATA:-/var/lib/postgresql/data}
  case "$data_dir" in
    /*) ;;
    *) fail "PGDATA must be an absolute path: $data_dir" ;;
  esac
  data_dir=${data_dir%/}
  [ -n "$data_dir" ] || fail "PGDATA must not be the filesystem root."

  version=$(postgres --version) || fail "Cannot read the configured server version."
  case "$version" in
    "postgres (PostgreSQL) "*) version=${version#postgres (PostgreSQL) } ;;
    *) fail "Unrecognized postgres --version output." ;;
  esac
  version=${version%% *}
  server_major=${version%%.*}
  case "$server_major" in
    ""|*[!0-9]*) fail "Cannot determine the server major version." ;;
  esac

  # Compose mounts the named volume at this path. Official PostgreSQL 18+
  # images default PGDATA to /var/lib/postgresql/<major>/docker, which is not
  # on that mount; an empty directory there is not a fresh durable cluster.
  volume_mount=/var/lib/postgresql/data
  if awk -v mp="$volume_mount" "\$5 == mp { found = 1 } END { exit !found }" /proc/self/mountinfo; then
    case "$data_dir" in
      "$volume_mount"|"$volume_mount"/*) ;;
      *) fail "PGDATA $data_dir is outside the mounted volume $volume_mount. Refusing to initialize a cluster that would not persist across container recreation." ;;
    esac
  fi

  # A changed PGDATA must not hide the standard volume. A partial directory
  # with no PG_VERSION is still existing data, not an unused mount.
  legacy_dir=$volume_mount
  if [ "$data_dir" != "$legacy_dir" ] && [ -e "$legacy_dir" ]; then
    if [ -e "$legacy_dir/PG_VERSION" ]; then
      fail "Existing cluster found at $legacy_dir, but PGDATA is $data_dir. Refusing to initialize another cluster."
    fi
    if [ ! -d "$legacy_dir" ]; then
      fail "Data path $legacy_dir exists but is not a directory, while PGDATA is $data_dir."
    fi
    legacy_entries=$(ls -A "$legacy_dir") || fail "Cannot inspect $legacy_dir."
    [ -z "$legacy_entries" ] || fail "Nonempty data directory at $legacy_dir has no PG_VERSION, but PGDATA is $data_dir. Refusing to initialize another cluster."
  fi

  if [ -e "$data_dir/PG_VERSION" ]; then
    [ -f "$data_dir/PG_VERSION" ] || fail "PG_VERSION is not a regular file."
    data_major=$(cat "$data_dir/PG_VERSION") || fail "Cannot read $data_dir/PG_VERSION."
    case "$data_major" in
      ""|*[!0-9]*) fail "Invalid PG_VERSION in $data_dir; refusing to treat it as an empty database." ;;
    esac
    if [ "$data_major" != "$server_major" ]; then
      fail "Data directory uses PostgreSQL $data_major, but the configured image runs PostgreSQL $server_major. Select the matching server image or explicitly migrate into a separate volume; restarting ARTEX cannot upgrade a PostgreSQL cluster."
    fi
    printf "PostgreSQL preflight: existing PG%s cluster matches server %s.\n" "$data_major" "$version"
  else
    if [ -e "$data_dir" ]; then
      [ -d "$data_dir" ] || fail "PGDATA is not a directory."
      entries=$(ls -A "$data_dir") || fail "Cannot inspect $data_dir."
      [ -z "$entries" ] || fail "Nonempty PGDATA has no PG_VERSION; refusing initialization."
    fi
    printf "PostgreSQL preflight: empty PGDATA; new PG%s cluster may be initialized.\n" "$server_major"
  fi
'
