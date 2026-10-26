# Traffic archive reference validation

## Decision before implementation (2026-10-26)

- Base: published blob-integrity fix `e814e2c17700d493aef8d7be92de1e3eca2af571`.
  This is a separate follow-on; its verification and staged-write behavior remain
  unchanged.
- Newly inserted exchanges must not commit missing, malformed or corrupt body
  references. Preserve current-row-wins, first duplicate wins, empty/inline
  bodies, and valid unlisted preexisting blobs in both supported layouts.
- Deliberately do **not** require every reference to be declared in `Blobs`:
  existing valid local reuse works today. Strict standalone-manifest membership
  is a separate compatibility decision, not needed to fix broken restoration.
- Validate selected references after `INSERT OR IGNORE` chooses a new row, within
  the same transaction. On failure roll back every exchange/body/reference/FTS
  row and report zero imported rows. Skip ignored duplicate references.
- Use the existing canonical lowercase SHA-256 identifier rule, verified archive
  hash set, `blobPath` layout resolution, and PR8's actual-byte verification.
  Cache verified hashes under the traffic writer lock to avoid repeated reads.
  Do not overwrite corruption, introduce dependencies, or alter the archive
  version, surrounding server lifecycle or unrelated permissions/visibility.
- Unlike the general blob-read API's user-input normalization, selected archive
  references must be exactly 64 lowercase hexadecimal characters, matching the
  existing manifest/producer identifiers. Previously accepted uppercase or
  whitespace-padded references are now rejected; stored IDs and GC keys are not
  normalized. Normal producer-generated archives already satisfy this rule.

## Evidence and references

Local review and synthetic probes on the exact base establish:

1. `traffic/archive.go:ExportHosts` collects every nonempty request/response
   reference and copies/lists its blob. Missing bytes fail export. The code calls
   the traffic snapshot portable; no separate normative missing-reference
   compatibility rule was found in the reviewed docs, schema or callers.
2. `ImportArchive` verifies only `snapshot.Blobs`, then writes unchecked selected
   exchange references. Fresh-store imports with unlisted references succeed,
   but full-body read and re-export fail, even if an unlisted file is in the
   archive directory. A valid first row followed by a missing-reference row
   returns `imported=2, err=nil` and commits both, instead of rejecting all.
3. An unlisted valid local blob works in current and legacy layouts; corrupted
   local bytes are likewise accepted and returned unchanged. Ignored duplicate
   references do not damage the current/first row.
4. `Get` can return a preview/pointer without reading a blob; validation must use
   actual bytes. `ReadEvidence` opens referenced bodies and detects missing ones.

Reference design only (no copied code or dependency):
[in-toto `verify_match_rule`](https://github.com/in-toto/in-toto/blob/e352b43ad7cb8915d84c36d791aa61346152a0a3/in_toto/verifylib.py#L645-L765)
requires destination existence and matching hashes. Prior research checked the
pinned source and [Apache-2.0 license](https://github.com/in-toto/in-toto/blob/e352b43ad7cb8915d84c36d791aa61346152a0a3/LICENSE);
this follow-on reuses that saved research rather than making new network calls.
ARTEX's separate `evidence/store.go:WithInstalledSnapshots` already validates
required bodies before restoring dependent metadata; reuse the principle, not
its PostgreSQL-specific implementation. ARTEX remains AGPL-3.0.

## Acceptance

- Reject missing, malformed and corrupt selected references on either side.
- Cover a bad last row: prior good rows, body rows, blob_refs and FTS entries
  must all roll back; return zero imported rows.
- A source file not listed in `Blobs` does not count as an installed local blob.
- Preserve valid unlisted local bytes, current and legacy layout, shared request
  and response hashes, valid listed blobs, inline bodies and idempotency.
- Preserve current-row and first-duplicate wins even if ignored references are bad.
- Run baseline failure, final focused/full traffic tests, race, vet and package
  build with synthetic/loopback fixtures and the existing local Go toolchain.

## Scope and risk boundaries

The server normally verifies the outer archive SHA before `ImportArchive` and
normal exporters include all referenced files. Ordinary post-creation package
modification is therefore blocked earlier. These tests establish an import
integrity/recoverability gap, not a remotely exploitable attack or authenticity
guarantee. Malformed references are rejected by `blobPath` before filesystem
access; no path traversal was established.

The traffic writer lock coordinates supported in-process writers, not unrelated
processes changing paths. Listed blob preparation can leave complete unreferenced
files after a later validation failure; only SQL metadata is transactional.
Power-loss guarantees, external hostile writers, signing, production restores,
and full PostgreSQL/server integration are outside this change.

## Verification

Executed in an isolated assistant-owned Linux/amd64 worktree with the existing
Go 1.27.2 toolchain and local caches, `GOTOOLCHAIN=local`, `GOPROXY=off`, and
`GOSUMDB=off`. The repository declares Go 1.26.3; exact-version CI is separate.
Fixtures are temporary synthetic data or the traffic suite's loopback fixtures;
no external scanner, target access, paid LLM, production restore, or network
dependency download was used.

| Check | Actual result |
| --- | --- |
| Exact published base + final new tests, focused run | Expected failure: 20 negative subtests accepted bad/noncanonical references; both positive compatibility groups passed (4 subtests). |
| Final `go test -p=2 -count=1 -json -timeout=120s ./traffic` | 60 top-level tests / 97 including subtests passed; zero failed or skipped. No exclusion filter. |
| Final `go test -race -p=2 -count=1 -json -timeout=180s ./traffic` | Same 60 / 97 passed; zero failed or skipped. |
| `go vet -p=2 ./traffic` | Passed. |
| `go build -p=2 ./traffic` | Passed affected-package build; not a full frontend/deployment build. |
| `git diff --check` | Passed. |

The new cases cover both body sides, a failing last row and all SQL metadata
tables (including FTS when enabled), source-only unlisted files, malformed and
noncanonical identifiers, empty/truncated/same-length-corrupt local files,
legacy layout, directory/symlink rejection, valid local reuse, shared hashes,
idempotency, and both duplicate-selection cases. Existing PR8 tests continue to
cover valid listed blobs and staged-write behavior.

The baseline failed because validation was absent, not because of environment
setup. Its tests and final tests are byte-for-byte identical. Neither Windows
runtime nor full PostgreSQL/server integration was executed here. The Windows
symlink fixture only skips explicit unsupported/privilege errors; this Linux
run skipped nothing.
