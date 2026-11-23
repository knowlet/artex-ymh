#!/usr/bin/env bash
# Inspect the configured PostgreSQL binary and mounted cluster before deployment.
# The official entrypoint is bypassed: this never starts postgres or runs initdb.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"

command -v docker >/dev/null 2>&1 || {
  echo "PostgreSQL preflight requires Docker / Compose." >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo "PostgreSQL preflight requires python3 to read the Compose config." >&2
  exit 1
}

# The official image declares VOLUME /var/lib/postgresql/data. Docker then
# mounts an anonymous volume there even when Compose did not. That mount
# satisfies a mountinfo check while the named project volume, and any cluster
# on it, stays detached. The effective config has to name the volume.
compose_config=$(docker compose config --format json) || {
  echo "PostgreSQL preflight: cannot read the effective Compose config." >&2
  exit 1
}
printf '%s\n' "$compose_config" | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.stderr.write("PostgreSQL preflight: Compose config is not valid JSON.\n")
    sys.exit(1)
services = doc.get("services") or {}
postgres = services.get("postgres") or {}
declared = doc.get("volumes") or {}
for mount in postgres.get("volumes") or []:
    if not isinstance(mount, dict):
        continue
    source = mount.get("source") or ""
    if (
        mount.get("type") == "volume"
        and mount.get("target") == "/var/lib/postgresql/data"
        and source
        and source in declared
    ):
        sys.exit(0)
sys.stderr.write(
    "PostgreSQL preflight: effective Compose config does not mount a named "
    "volume at /var/lib/postgresql/data. An anonymous volume from the image "
    "is not the project data volume.\n"
)
sys.stderr.write("Keep the existing data volume. See docs/POSTGRES-UPGRADE.md.\n")
sys.exit(1)
'

# Compose resolves .env, COMPOSE_FILE/COMPOSE_PROJECT_NAME, image overrides and
# PGDATA exactly as it does for the real service. Do not infer a major from a tag
# or assume that the current directory determines the deployed volume name.
docker compose run --rm --no-deps -T --entrypoint sh postgres -ec "$(cat <<'EOS'
fail() {
  printf "PostgreSQL preflight: %s\n" "$*" >&2
  printf "Keep the existing data volume. See docs/POSTGRES-UPGRADE.md.\n" >&2
  exit 1
}

# Physical path, including ".." and symlinks. Components that do not exist yet
# stay lexical, and ".." still walks back out of them.
resolve_path() {
  input=$1
  acc=/
  rest=${input#/}
  while [ -n "$rest" ]; do
    seg=${rest%%/*}
    case "$rest" in
      */*) rest=${rest#*/} ;;
      *) rest= ;;
    esac
    if [ -z "$seg" ] || [ "$seg" = "." ]; then
      continue
    fi
    if [ "$seg" = ".." ]; then
      if [ -d "$acc" ]; then
        acc=$(CDPATH='' cd -P -- "$acc/.." && pwd -P) || return 1
      else
        acc=${acc%/*}
        [ -n "$acc" ] || acc=/
      fi
      continue
    fi
    if [ "$acc" = / ]; then
      next=/$seg
    else
      next=$acc/$seg
    fi
    if [ -d "$next" ]; then
      acc=$(CDPATH='' cd -P -- "$next" && pwd -P) || return 1
    elif [ -e "$next" ]; then
      return 1
    else
      acc=$next
    fi
  done
  printf '%s\n' "$acc"
}

# Longest mount point covering the path: the filesystem that would hold it.
mount_covering() {
  awk -v path="$1" '
    function covers(mp, p) {
      if (mp == "/") return 1
      return p == mp || index(p, mp "/") == 1
    }
    {
      mp = $5
      gsub(/\\040/, " ", mp)
      if (covers(mp, path) && length(mp) >= length(best)) best = mp
    }
    END {
      if (best == "") exit 1
      print best
    }
  ' /proc/self/mountinfo
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
# A textual prefix is not enough: data/../other and a symlink or nested mount
# under the mount point can be backed by a different filesystem.
volume_mount=/var/lib/postgresql/data
resolved=$(resolve_path "$data_dir") || fail "Cannot resolve PGDATA $data_dir."
volume_phys=$(resolve_path "$volume_mount") || fail "Cannot resolve the mounted volume $volume_mount."
# The named volume has to be mounted. Skipping this when it is absent accepts
# an empty image-default PGDATA and lets initdb write outside pgdata.
if ! awk -v mp="$volume_mount" '$5 == mp { found = 1 } END { exit !found }' /proc/self/mountinfo; then
  fail "Named volume is not mounted at $volume_mount. Refusing to initialize a cluster that would not persist across container recreation."
fi
data_mount=$(mount_covering "$resolved") || fail "Cannot determine the mount backing PGDATA $data_dir."
volume_backing=$(mount_covering "$volume_phys") || fail "Cannot determine the mount backing $volume_mount."
if [ "$data_mount" != "$volume_backing" ]; then
  fail "PGDATA $data_dir is outside the mounted volume $volume_mount. Refusing to initialize a cluster that would not persist across container recreation."
fi

# Reject a standard directory that is not the configured cluster. Compare the
# physical paths: /var/lib/postgresql/data/../data and a symlink to that
# directory are the same cluster, not a second one. A PGDATA inside the
# volume (…/data/pgdata) makes the parent nonempty; that parent is the
# cluster's ancestor, not unrelated data, unless it has its own PG_VERSION
# or any entry other than the path down to PGDATA.
reject_legacy_contents() {
  dir=$1
  shown=$2
  if [ -e "$dir/PG_VERSION" ]; then
    fail "Existing cluster found at $dir, but PGDATA is $shown. Refusing to initialize another cluster."
  fi
  if [ ! -d "$dir" ]; then
    fail "Data path $dir exists but is not a directory, while PGDATA is $shown."
  fi
  hidden_entries=$(ls -A "$dir") || fail "Cannot inspect $dir."
  [ -z "$hidden_entries" ] || fail "Nonempty data directory at $dir has no PG_VERSION, but PGDATA is $shown. Refusing to initialize another cluster."
}

reject_legacy_siblings() {
  dir=$1
  seg=$2
  shown=$3
  hidden_other=
  if [ ! -e "$dir" ]; then
    return 0
  fi
  if [ -e "$dir/PG_VERSION" ]; then
    fail "Existing cluster found at $dir, but PGDATA is $shown. Refusing to initialize another cluster."
  fi
  if [ ! -d "$dir" ]; then
    fail "Data path $dir exists but is not a directory, while PGDATA is $shown."
  fi
  hidden_entries=$(ls -A "$dir") || fail "Cannot inspect $dir."
  while IFS= read -r hidden_entry; do
    [ -n "$hidden_entry" ] || continue
    [ "$hidden_entry" = "$seg" ] && continue
    hidden_other=1
    break
  done <<EOF
$hidden_entries
EOF
  [ -z "$hidden_other" ] || fail "Nonempty data directory at $dir has no PG_VERSION, but PGDATA is $shown. Refusing to initialize another cluster."
}

if [ "$resolved" != "$volume_phys" ] && [ -e "$volume_phys" ]; then
  case "$resolved" in
    "$volume_phys"/*)
      hidden_cursor=$volume_phys
      hidden_rest=${resolved#"$volume_phys"/}
      while [ -n "$hidden_rest" ]; do
        hidden_seg=${hidden_rest%%/*}
        case "$hidden_rest" in
          */*) hidden_rest=${hidden_rest#*/} ;;
          *) hidden_rest= ;;
        esac
        reject_legacy_siblings "$hidden_cursor" "$hidden_seg" "$data_dir"
        if [ "$hidden_cursor" = / ]; then
          hidden_cursor=/$hidden_seg
        else
          hidden_cursor=$hidden_cursor/$hidden_seg
        fi
      done
      ;;
    *)
      reject_legacy_contents "$volume_phys" "$data_dir"
      ;;
  esac
fi

# Read the cluster at the resolved path. PGDATA=/var/lib/postgresql/data/missing/..
# does not exist until "missing" is created, so the raw path hides PG_VERSION
# that ".." walks back onto.
if [ -e "$resolved/PG_VERSION" ]; then
  [ -f "$resolved/PG_VERSION" ] || fail "PG_VERSION is not a regular file."
  data_major=$(cat "$resolved/PG_VERSION") || fail "Cannot read $resolved/PG_VERSION."
  case "$data_major" in
    ""|*[!0-9]*) fail "Invalid PG_VERSION in $data_dir; refusing to treat it as an empty database." ;;
  esac
  if [ "$data_major" != "$server_major" ]; then
    fail "Data directory uses PostgreSQL $data_major, but the configured image runs PostgreSQL $server_major. Select the matching server image or explicitly migrate into a separate volume; restarting ARTEX cannot upgrade a PostgreSQL cluster."
  fi
  printf "PostgreSQL preflight: existing PG%s cluster matches server %s.\n" "$data_major" "$version"
else
  if [ -e "$resolved" ]; then
    [ -d "$resolved" ] || fail "PGDATA is not a directory."
    entries=$(ls -A "$resolved") || fail "Cannot inspect $resolved."
    [ -z "$entries" ] || fail "Nonempty PGDATA has no PG_VERSION; refusing initialization."
  fi
  printf "PostgreSQL preflight: empty PGDATA; new PG%s cluster may be initialized.\n" "$server_major"
fi
EOS
)"
