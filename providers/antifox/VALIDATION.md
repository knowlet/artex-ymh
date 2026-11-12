# AntiFox integration validation — 2026-11-12

## Environment and identity

- ARTEX base: `f10a1941c12529aba5d89159d18cbc1fd7e7c153`.
- Branch: `codex/integrate-antifox-20261112`, isolated from the original dirty
  checkout. No existing uncommitted file was copied over or overwritten.
- AntiFox source: `070f798bf590667bc2a0a13c687dd87d8a4413bf`.
- macOS arm64; Go 1.27.3; Python 3.15.2; PostgreSQL 15.19 (Homebrew).
- PostgreSQL tests used newly created disposable databases on loopback port
  59342. They did not use the deployed application database or launch tasks.

## Executed checks

| Check | Result and evidence boundary |
| --- | --- |
| `python3 scripts/sync_antifox.py --check` | PASS: all 86 distributed adapter/resource files match the reviewed source/conversion. 23 source skill identities, root license, and 17 report resources are hash-bound. |
| `python3 -m unittest discover -s scripts -p test_sync_antifox.py -v` | PASS: 7 tests, no skips. Includes source/resource tampering, symlink output refusal, preservation of operator edits, and deterministic generation. |
| `python3 -m unittest discover -s scripts -p test_discovery_distribution.py -v` | PASS: 3 tests, including Linux/Windows archive subcases. The real bundle is packaged and rechecked after extraction. The compiler is a test double; Docker COPY declarations are staged against real inputs. This is not a real cross-platform executable or Docker image build. |
| `go test -race ./skillknowledge ./skillcheck -count=1` | PASS: actual Norma v0.4.3 load/invoke for all 23 adapters; source/license preservation; no MCP activation; 3 existing skills reused without duplication; 6 representative English/Traditional Chinese retrieval queries; malformed input, bounds, cancellation, immutable snapshots and concurrent calls. No skips. |
| `go test -race ./db ./server -run '^(TestBuiltinSkillRevocationSurvivesStartup\|TestSkillRevocationDoesNotTouchAnotherLibrary\|TestAntiFoxKnowledgeVisibilityPG)$' -count=1 -v` with the disposable `ARTEX_PG_DSN` | PASS: 3 top-level real PostgreSQL tests. Covers individual/bulk revocation across startup, same-name library separation, raw augmentation before tool resolution, preservation of custom same-name tools, hidden/revoked skills, editable tool disables and malformed provider identity. No skips. |
| `go test -p 1 -json ./... -count=1` with a **fresh** disposable `ARTEX_PG_DSN` and `ARTEX_ANTIFOX_REQUIRE_PG=1` | PASS: 1,224 top-level tests passed, 39 top-level tests skipped, zero failed; counting subtests gives 1,996 pass events and 43 skip events. 30 packages passed; 2 packages have no test files. |
| `go vet ./...` | PASS. |
| `go build -o /private/tmp/artex-antifox-20261112 ./cmd/artex` | PASS: real macOS/arm64 backend executable from the validated working tree. SHA-256 `d7bcd97b308b26197a374c37c05825e008bf975f61696e2d584cbc453b9c3c56`. |
| `/private/tmp/artex-antifox-20261112 -h` | PASS: actual CLI startup/help exits 0 without database/server initialization. |
| `bash -n build.sh`, first-party `git diff --check`, formatting | PASS. Verbatim upstream snapshots and derived skill documents retain upstream whitespace; their identity is checked separately. |

The focused CI workflow is added in `.github/workflows/antifox-tests.yml` with a
pinned PostgreSQL 16 image. No push occurred, so remote CI has not run.

## Failures investigated during validation

The first real visibility test failed because a disabled shipped skill was
restored by startup seeding. The single toggle and bulk setter deleted rows;
startup treats an absent row as a default that has never been seeded. The fix
keeps explicit disabled rows. Generic regressions also cover the existing
`api-recon` default and ensure one library's revocation cannot disable another
library's same-name grant. A test fixture initially used a UUID containing
disallowed hyphens in an agent key; the fixture now follows the existing schema.

The first broad parallel run reported a database deadlock in `TestConfirmFact`
and a missing `llm_usage` relation in a recording test. A subsequent serialized
run reusing that populated database hit `TestCompanyScopeAttribution`, whose
previous run had retained a company CIDR. These failures are retained in the
local run logs; they were not fixed by changing application behavior or test
expectations. Complete serialized runs on fresh disposable databases passed.
The final fresh run includes the final metadata/output bounds.

Review of the Linux-only provider integration contract revealed that callers also
inspect raw augmentation before the usual tool resolver. An added PG assertion
first failed because an unbound custom agent received the two new tools. Tool
bindings are now checked before augmentation as well as by the final resolver;
the regression passes and existing same-name custom tools are preserved. The
Linux CI workflow includes the original provider integration test, which remains
unverified locally because the importer intentionally requires Linux filesystem
primitives. The final delivery run also includes this assembly correction.

The distribution fixture initially lacked the newly required provider directory;
it now packages the real reviewed source/adapters and verifies them after archive
extraction and Docker-context staging, retaining the original integrity checks.

A full staged whitespace check reports upstream trailing spaces in the retained
documents (including a filename-bypass example). Those source bytes are preserved
under their recorded hashes rather than silently rewritten. First-party source,
scripts, configuration and documentation pass the whitespace check; the generated
bundle passes its exact-byte check.

## Skipped and unverified work

The 39 skipped top-level tests require Linux-specific provider/managed-scanner
support, separate `ARTEX_AUTH_TEST_DSN` setup, a private live-model configuration,
PHP or a real suo5 payload directory. They are not counted as passed. The source
tree, CLI help, mocks and in-process PG assembly do not establish LLM task success.

No production deployment/restart, frontend browser acceptance, live LLM run,
external scanner installation or external target test was performed. AntiFox's
pgvector/global-task document service, DOCX report engine and dedicated report UI
are not implemented by this integration. The two knowledge tools search only the
current agent's authorized skill reference passages. Existing source scope,
approval, MCP, evidence-version and tool-binding controls remain the runtime
boundaries.
