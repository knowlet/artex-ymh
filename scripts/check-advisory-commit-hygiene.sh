#!/usr/bin/env bash
# Refuse tracked secrets/build artifacts in the approval-advisory slice.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "commit hygiene: $1" >&2
  exit 1
}

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  for path in server/jwt.key jwt.key web/out; do
    if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
      fail "forbidden tracked path: $path (remove from index; history may still contain it)"
    fi
  done
fi

if [[ -f server/jwt.key ]]; then
  fail "server/jwt.key exists in workspace — delete and use dataDir/temp keys only"
fi
