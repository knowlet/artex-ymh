# ARTEX dependency upgrade — migration & rollback (2026-11-11)

## Scope

Runtime dependency bumps (Go modules, npm lockfile, Docker Node/Playwright pins). **No** PostgreSQL major migration, **no** schema.sql semantic changes, **no** production deploy.

## Order of operations

1. **Backup** — `pg_dump -Fc` of operator DB; copy `data/` (config, keys, archives) to dated snapshot. Required before any prod attempt; disposable rehearsals use throwaway DBs only.
2. **Stop writers** — `systemctl stop artex` or `docker compose stop artex`; confirm no active tasks (`/api/tasks` idle).
3. **Replace artifact** — new binary or image from this branch tag; config.json unchanged unless release notes say otherwise.
4. **Start** — `schema.sql` re-`Exec` on boot (idempotent DDL); `llmRecordsMigrate` and inline migrations run once per missing column.
5. **Verify** — login, gate path, one task list fetch, `SELECT max(updated_at) FROM tasks`; compare app version string.

## Schema / data compatibility

- Single source: `db/schema.sql` (idempotent). Existing installs upgrade **in place** on first startup after binary swap.
- **Rehearsed path**: `db/llm_records_migrate_test.go` — strips `raw_*` columns, applies `llmRecordsMigrate`, asserts idempotency (transaction rolled back; real PG).
- **Fresh install**: empty DB → full `schema.sql` via `db.Open` (covered by PG security regressions when `ARTEX_PG_DSN` set).

## Version ladder

| Step | From | To | Reversible |
| --- | --- | --- | --- |
| App binary + embed UI | prior release | this commit | Yes — redeploy prior binary |
| Go/stdlib deps | go.mod prior | go.mod this branch | Yes — rebuild old tag |
| npm bundle | prior lock | new lock | Yes — rebuild old tag |
| Docker runtime Node | 20/22.14 | 22.23.4 tarball | Yes — rebuild old Dockerfile tag |
| Playwright in image | 1.63 | 1.65 | Yes — rebuild; browser cache mismatch may need `playwright install` once |
| PostgreSQL server | 16.x | 16.x (held) | N/A this PR |

**Irreversible upgrades (not in this PR)**: PostgreSQL 16→17 dump/restore; Node 22→24 default; Go 1.26→1.27 toolchain default in CI.

## Downtime

- Single-instance: brief stop/start (seconds–minutes) while binary swaps; schema migrations are online DDL where supported.
- No long-running data backfill in this change set.

## Abort criteria

- Startup fails on `db.Open` / migration error in logs.
- `go test` / security-regressions equivalent fails on disposable PG.
- Frontend static build or `tsc` fails.

## Rollback procedure

1. Stop service.
2. Restore **previous** container image or `artex` binary from last known-good SHA (release artifact or local build).
3. Restore DB only if a failed migration partially applied (rare — most DDL is `IF NOT EXISTS`). If needed: `pg_restore` from pre-upgrade dump.
4. Start previous version; confirm gate + auth.

## Evidence (this branch)

Produced under `packaging/upgrades/evidence/` by `scripts/verify_upgrade_gates.sh` with disposable `ARTEX_PG_DSN`. CI on the draft PR is authoritative for merge readiness; local logs are rehearsal only.

## PR15 / PR17

Read-only comparison: no manifest conflicts. Merge order recommendation: land this upgrade first or rebase security PRs onto it; **do not** cherry-pick advisory/jwt work from PR15 into this branch.
