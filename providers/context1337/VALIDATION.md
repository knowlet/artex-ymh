# Context1337 exercise validation — 2026-11-26

Validated in an isolated checkout based on
`f4cabd35ff33b028eeeb632547898c0609bffa7c`, continuing draft PR #33.
The commit containing this record identifies the tested implementation; final
remote-head CI runs/results are reported in the PR description.

Environment: Go 1.27.4, darwin/arm64; isolated temporary module/build caches.
Integration tests use PostgreSQL 15 in a new disposable local cluster, not an
ARTEX operational database. Provider CI uses its disposable PostgreSQL 17 service.

## Executed

All commands below exited 0. No selected tests were skipped.

| Command | Observed result |
| --- | --- |
| `go test -race ./context1337 -count=1 -v` | 12 top-level tests passed, plus subtests: strict inputs/projection, HTTP failures/filters, cancellation, 3-second deadline, four shared slots and cleanup. |
| `go test -race ./cmd/artex/context1337.go ./cmd/artex/context1337_test.go -count=1 -v` | 7 top-level CLI tests passed, plus subtests; same standalone entry remains available. |
| `go test -race ./agent -run '^(TestContext1337\|TestCapabilityGuidance\|TestBuiltinToolSeeds)' -count=1 -v` | 6 top-level tests passed, including planner/worker subtests: unbound catalog, final permitted-tool guidance, no default/taskless exposure. |
| `ARTEX_CONTEXT1337_REQUIRE_PG=1 go test -race -json ./server -run '^TestContext1337' -count=1` with disposable DSN | 3 top-level tests passed, plus key-file subtests. `TestContext1337ExercisePG` actually executed against PostgreSQL and local mock HTTP. |
| `python3 scripts/assert_go_test_results.py <server-jsonl> github.com/Autumn-27/artex/server TestContext1337ExercisePG` | Verified the required PG test ran and passed; no vacuous/skip success. |
| `go test -race ./intelpack ./skillknowledge -count=1 -v` | 13 top-level offline regression tests passed, plus subtests. |
| `go vet ./context1337 ./agent ./server ./cmd/artex` | Passed. |
| `go build -o <temporary-artifact> ./cmd/artex` | Backend compiled. |
| Built backend `intel status --data-pack packaging/discovery-data-manifest.json` | Offline hashes and distinct KEV/Nuclei provenance reported without service/database startup. |
| Built backend `context1337 search --help` | Actual CLI dispatch exited 0 without service/database startup. |
| `actionlint .github/workflows/discovery-tests.yml .github/workflows/provider-tests.yml` | Passed; workflows remain test-only on PR events. |
| `gofmt -l` for changed Go files; `git diff --check` | No formatting/whitespace errors. |

The PG test checks both raw augmentation and final tool resolution, explicit
enable/binding, exact task allowlist, live task/exploration identity, wrong-role
and taskless rejection, binding revocation, disabled/custom/nonbuiltin rows,
paused/queued/finished/expired/deleted tasks, and database outage while request
quota remains. The healthy call after DB restoration succeeds. Both roles share
the 16-request budget, including provider failures. Finding and exploration-node
counts and task state remain unchanged by metadata calls (normal tool usage
metering still records calls).

Two refinements were verified during development: explicit empty `source` was
first shown to violate the input enum, then rejected by the handler; the DB
outage case was moved before quota exhaustion so it distinguishes the intended
failure from budget denial. Initial restricted HTTP/PG attempts could not bind
loopback or allocate shared memory; approved local fixture executions above
passed. No product assertion failures remain in the final runs.

## Limits

- No live Context1337 deployment, real API key or live model-driven exercise was
  used. Mock/PG results establish adapter and authorization behavior, not live
  compatibility or model compliance.
- Key least privilege is operator-provisioned (`read`, `builtin`, includes
  nuclei); the provider API has no effective-permissions attestation endpoint.
  A private file avoids environment secret-value inheritance, but same-UID
  Bash/Read remains able to read files permitted to ARTEX.
- The upstream FTS first page is incomplete; absence is not a safety conclusion.
  Metadata is unverified external reference material, never target evidence.
- The request quota is process-local and resets on restart. Binding/state changes
  deny the next call; cancellation interrupts in-flight work. A dispatched
  request can otherwise finish within its deadline.
- No merge, deployment, upstream code/corpus redistribution or external target
  test was performed. The original working directory's changes were preserved.
