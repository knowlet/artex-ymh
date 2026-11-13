# ARTEX dependency upgrade — migration & rollback (2026-11-11)

## Scope

Runtime dependency bumps (Go 1.27.4, PostgreSQL **17**, npm, Docker pins). Schema source remains `db/schema.sql` (idempotent). **Not** a production deploy.

## PostgreSQL major (16 → 17) — supported path

**Rehearsed** (`scripts/rehearse_pg16_to_pg17_major.sh` → `packaging/upgrades/evidence/pg-major-migration-evidence.json`):

1. Run **pre-cutover** binary built from **`main`** (Go 1.26.3) against **PostgreSQL 16**.
2. Seed auth, `companies`, `tasks`, and `data/` marker files.
3. **`pg_dump -Fc` using the PG16 client** (matches source server major).
4. Restore into a **fresh PostgreSQL 17** database with **`pg_restore` (PG17 client)** — supported logical upgrade. **`pg_upgrade` not used** in this rehearsal.
5. Run **upgrade-branch** binary on PG17; verify login, row counts, task name.
6. **Rollback:** restore the **same PRE-cutover PG16 dump** into a **fresh PG16** database; run **baseline `main` binary**; verify rows + auth.

**Not supported / not claimed:**

- Importing a **PostgreSQL 17** dump into **16** (rehearsal observed `pg_restore: unsupported version (1.16) in file header` when attempting PG17 dump → PG16).

**Cutover / rollback boundaries:**

- Rollback DB state = **instant of PRE-cutover backup** only.
- **Post-cutover writes** on PG17 (and filesystem deltas after backup, e.g. `post-cutover-write` in `data/`) are **lost** on DB rollback unless separately reconciled.
- After major cutover, **downgrade without a PG16-era backup is restore-only impossible** for DB contents.

## Go toolchain (1.26 → 1.27.4)

- **Not intrinsically data-irreversible**: redeploy a binary built from the prior tag/`main` with Go 1.26.x.
- Distinct from **PostgreSQL major** rollback, which requires a **matching-era logical backup**.

## App schema migrations (same major)

- `schema.sql` on startup; `llmRecordsMigrate` for legacy columns (`db/llm_records_migrate_test.go`).
- Rehearsed on PG17 in addition to full PG major script above.

## Operator checklist

1. Stop writers; `pg_dump -Fc` on **PG16** with **PG16 client**.
2. Restore to PG17 test instance; smoke upgrade binary.
3. Cutover production; **keep PG16 dump** until PG17 stable.
4. Rollback: stop app → restore **PG16 dump** to PG16 → deploy **prior** binary tag.

## Evidence

- `packaging/upgrades/evidence/pg-major-migration-evidence.json`
- `packaging/upgrades/evidence/TEST-SUMMARY-2026-11-11.json`
- CI on draft PR #18 at merge head.

PR15/PR17: not merged here; jwt historical exposure **out of scope**.
