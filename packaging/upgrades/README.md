# Dependency upgrade pack (2026-11-11)

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

Browser smoke (real Playwright, isolated from PR15 advisory suite):

```bash
cd packaging/upgrades/e2e && npm ci && npx playwright install chromium
# start local artex with embed UI + PG, then:
ARTEX_E2E_BASE_URL=http://127.0.0.1:8787 npx playwright test
```
