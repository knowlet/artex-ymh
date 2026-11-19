# Dependency upgrade pack (2026-11-11)

## Deployment correction (2026-11-19)

This directory records the **historical dependency-upgrade rehearsal**, not an
automatic production PostgreSQL migration. PR #18 changed Compose from PG16 to
PG17 without converting existing named volumes; its disposable dump/restore
tests did not cover starting PG17 against a populated PG16 deployment volume.

Compose now defaults to PG16 for existing installations. Already-initialized
PG17 installations must retain `POSTGRES_IMAGE=postgres:17-alpine`. The
deployment preflight checks image/data major compatibility and does not migrate
data. Use the [current PostgreSQL recovery and upgrade guide](../../docs/POSTGRES-UPGRADE.md)
for recovery, an intentional migration to a separate volume, and rollback
boundaries. The inventory, matrix and evidence below remain dated snapshots;
their PG17 target is not the default deployment policy.

Machine-readable artifacts for the comprehensive upgrade branch:

| File | Purpose |
| --- | --- |
| `inventory-2026-11-11.json` | Snapshot of Go direct modules, npm packages, Docker bases, GH Action pins |
| `matrix-2026-11-11.json` | Current → target table with holds and PR15/17 integration notes |
| `MIGRATION-ROLLBACK-2026-11-11.md` | Deploy order, rollback, abort criteria |
| `evidence/TEST-SUMMARY-2026-11-11.json` | Local rehearsal outcomes (disposable DB/credentials only) |

Regenerate inventory:

```bash
python3 scripts/collect_upgrade_inventory.py
```

Reproduce gates (requires disposable `ARTEX_PG_DSN`):

```bash
export ARTEX_PG_DSN='postgres://artex_test:disposable_test_password@localhost:5432/artex_test_fresh?sslmode=disable'
export ARTEX_AUTH_TEST_DSN="$ARTEX_PG_DSN"
scripts/verify_upgrade_gates.sh
scripts/run_security_audits.sh
```

PostgreSQL major rehearsal (disposable PG16 dump → PG17 → rollback on PG16;
never point this script at production containers or databases):

```bash
# Requires docker containers artex-pg16 and artex-pg17; builds baseline from main worktree.
scripts/rehearse_pg16_to_pg17_major.sh
```

Browser smoke (real Playwright, isolated from PR15 advisory suite):

```bash
cd packaging/upgrades/e2e && npm ci && npx playwright install chromium
# start local artex with embed UI + PG, then:
ARTEX_E2E_BASE_URL=http://127.0.0.1:8787 npx playwright test
```

Findings export, task report, and upload byte round-trip (disposable PG17 + deterministic seed):

```bash
# Requires PostgreSQL on ARTEX_PG_HOST:ARTEX_PG_PORT (default 127.0.0.1:5433).
scripts/rehearse_findings_report_e2e.sh
```
