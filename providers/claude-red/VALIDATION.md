# Provider validation

Baseline: `5cddfce1fd7de9ffde26bacbf5e6366b49019492` (main, including PR #4).
Environment: Linux/amd64; official Go 1.26.3 archive SHA-256
`2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556`.
Dependencies remain pinned by existing go.mod/go.sum (Norma v0.4.3).

## Local evidence

- `go test -race ./skillprovider -count=1`: passed. Original harmless modern and
  legacy source fixtures exercise the actual Norma loader, byte preservation,
  per-document licensing, strict catalog/source validation, confinement,
  atomic publication, cancellation and receipt/readiness integrity.
- `go vet ./skillprovider`: passed.
- From `cmd/artex`, `GOPROXY=off go test provider.go provider_test.go -count=1 -v`:
  passed the CLI/static checks using the production command and
  actual importer. This excludes full main/server linking.
- `go test -c ./skillprovider` followed by
  `strace -f -e trace=execve,execveat,network` of
  `TestProviderImportNormaContract`: passed; only the initial test executable was
  executed, with no additional exec or network syscalls. This observation covers
  that real harmless conversion test, not every possible ARTEX operation.
- `gofmt` and `git diff --check`: passed.
- All 79 upstream source byte sequences were compared against the pinned tree's
  Git blob SHA-1 and size, then recorded by SHA-256 in the catalog. No original
  skill content was added to a loadable directory.

## Earlier executor blockers

These blockers describe the earlier Linux executor used for the initial PR.
The later local-container follow-up below has all dependencies and real PostgreSQL.

The earlier executor's `/usr/bin/go` is unrelated to Golang, so the verified official
compiler was unpacked under /tmp. Download of existing klauspost/compress
v1.18.6, modernc/sqlite v1.52.0 and modernc/libc v1.72.3 from the Go proxy's
storage redirect was denied with HTTP 403 by the network proxy. No alternate
route was used. An offline full backend build fails due to the missing modules.
This is an environment dependency blocker, not a reproduced program regression.

A disposable PostgreSQL 16-alpine test service became healthy locally, but the
server integration test could not compile without those modules. A healthy
service alone is not visibility/metering verification. No local full-repository
baseline test run is claimed.

## Remote CI and capability boundaries

The dedicated provider workflow requires real PostgreSQL (no skip), actual
importer -> Norma Skill invocation -> visibility and usage ledger, unknown-skill
miss attribution, fresh-run revocation, absent file/agent, provider race tests,
CLI tests, syscall trace, vet and backend build. Its results must be checked
against the exact pushed PR head and synthetic merge commit. CI links and
outcomes are recorded in the PR description and delivery report.

No third-party binary, API, runtime, attack adapter, LLM or target environment
was exercised. Metadata, alias mapping, source hashes and tests do not establish
that any of the 79 catalog entries or 85 tool families are executable. All
bundled entries remain metadata-only/provenance-unverified; all offline agent,
registration, binary and runtime evidence remains unknown. Existing traffic
workflow and scope/approval/cancel/isolation logic are unchanged.

## Historical review follow-up against head 2eb4b35

Independent baseline reproduction used the actual provider command and harmless
synthetic fixtures. SIGINT/SIGTERM during staging terminated the old command and
left one staging directory. A real closed stdout pipe terminated it with SIGPIPE
even though `Inspect` verified a committed library. A synthetic output writer
failure also reported only an ordinary failure after commit, and retry was
correctly refused by the unchanged no-replace contract.

The revised command uses a shared signal wrapper with NotifyContext for ordinary
interrupt/termination and temporary SIGPIPE notification for observable output
errors. Regressions cover real signals during staging, a real closed stdout pipe,
zero/partial report failures after verified commit, retained existing-destination
refusal, and SIGKILL residual staging that later imports do not delete. Exit 3
explicitly means committed-but-output-failed. Cooperative signal cleanup is
separate from the documented uncatchable crash/SIGKILL limitation.

The real PG test now also checks the existing name-based identity limitation:
a pre-existing same-name grant follows a configured replacement library, a
new namespace does not inherit that particular grant, and revoking matching
grants before switching prevents visibility in a fresh run. No production DB
schema, binding, assembly or metering logic is changed. That was the pre-fix behavior; the library identity follow-up below replaces
this limitation with scoped grants and regressions that require rejection.

Relative catalog/source/destination paths under a symlink-form PWD were rejected
by the old filepath.Abs-based walk. A baseline overlay reproduces that failure;
regressions now exercise the descriptor-relative implementation while explicit
symlink components and traversal still fail closed.

Filesystem tests now distinguish Linux backend coverage from portable metadata
validation and the unsupported-backend contract. Linux-host execution of the
actual unsupported stub tests does not count as a Darwin/Windows runtime test.
Darwin/Windows compilation checks do not execute foreign binaries. No broader
runtime support or recovery architecture is claimed.

Local follow-up results: Linux `go test -race ./skillprovider -count=1` passed
128 tests/subtests with zero skips; the production provider command file tests
also passed under `-race`, including actual OS signals and closed-pipe output.
Provider and CLI test binaries compiled for Darwin/amd64 and Windows/amd64;
they were not executed. Positive unsupported provider/CLI backend tests and
portable metadata tests passed using the actual unsupported stub on the Linux
host. The workspace dependency-download blocker still prevents a local full
backend/PG build; the PR records the new head's dedicated remote CI results.

## Library identity and explicit stage recovery follow-up

Starting head: `ff1927d819be70972aeb4b4edd71167e1ce65f57`.
Local runtime: disposable Linux/arm64 containers, Go 1.26.3, PostgreSQL 16.15,
locked repository dependencies. No deployment, real target, LLM, MCP or external
tool execution was part of this validation.

- `go test -race ./skillprovider -count=1 -json`: **157 tests/subtests passed,
  zero skips**. Includes unique import identities, receipt/marker agreement,
  actual SIGKILL followed by explicit recovery, active-stage refusal and complete
  preservation when unknown/modified/incomplete/symlink/hardlinked content exists.
- `go test -race ./cmd/artex -run '^TestProvider' -count=1 -json`: **23
  tests/subtests passed, zero skips**. Includes recovery argument validation and
  output failure, real SIGINT/SIGTERM and closed stdout regression checks.
- `go test -race ./server -run
  '^(TestProviderVisibilityAndMeteringPG|TestAssembleVisibleSkill|TestSkillTools)$'
  -count=1 -json`: **4 tests/subtests passed, zero skips** with required real PG.
  Covers old generic grants and same-name replacement rejection, explicit grants
  through visibility APIs, scoped bulk grant/revocation, deleted/corrupt receipt
  rejection, actual Norma guidance/metering and ordinary legacy skills.
- `go vet ./skillprovider ./cmd/artex ./server` and full backend build: passed.
- The workflow's actual unsupported provider/CLI backend commands passed on Linux;
  recovery uses the existing filesystem implementation/stub, so the workflow
  and its permissions are unchanged.
- Darwin/amd64 and Windows/amd64 provider/CLI test binaries compiled. Foreign
  runtime execution remains unverified. The built backend offline status returned
  all 79 metadata-only entries with missing imports and unknown agent visibility
  while its database DSN was deliberately unavailable.

Each import now generates a random library ID, retained in its receipt and root
marker. The DB migration adds an empty-default `library_id` scope to preserve
ordinary legacy grants. Earlier provider receipts must be reimported and granted
again. Regressions first reproduced a receipt-loss downgrade to a legacy grant;
the retained marker now makes that case fail closed. Both identity files must be
preserved; they do not establish trust against an operator able to rewrite both.

Recovery is explicit for one exact stage path. A locked, private, inode-bound
inventory permits missing expected files but refuses changed or unknown content.
A process killed before completing the inventory, an incomplete file or an I/O
cleanup failure can still require manual review. No prefix/age sweep is added.

Final remote head, CI run/job links and outcomes are recorded in the PR delivery
report. Earlier CI results in this document do not certify a later head.
