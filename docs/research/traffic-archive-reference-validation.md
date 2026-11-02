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

## Integration after PR #8 squash (2026-11-02)

Base is now `4e171f347c2c28a55205f74fce20dd1661b3074c`. Merge main into
the follow-on branch without rewriting its history. Unlike the initial design
above, unlisted references are fully hashed before taking the recording mutex.
Their selected path and file identity are rechecked under the mutex before any
selected row commits; concurrent removal, replacement, or legacy-path shadowing
fails closed and asks the caller to retry. Hash errors remain deferred until a
row is selected, preserving current-row-wins and first duplicate wins. Repeated
archive IDs are not scanned again. A read-only existence check skips reference hashing for already-present rows.
If concurrent deletion makes an unprepared row selectable, import fails closed
with an explicit retry error; it never hashes under the recording lock.
No wire format or database schema changes. Added deterministic paused-hash tests
cover recording, removal, replacement, layout shadowing, and concurrent current
row insertion for both supported layouts.

Integration verification on assistant-owned Linux/amd64, Go 1.27.2: full traffic
and race runs each passed 66 top-level tests / 117 including subtests, with no
failures or skips. Vet, affected-package build and diff whitespace checks passed.
Concurrent replacement fixtures publish a separate inode by rename; in-place
mtime fixtures explicitly set a different timestamp. Verification-entry waits
also detect early return or timeout instead of silently hanging. These are local
synthetic tests; post-push CI, external review and final rerun are separate gates.

## External-review follow-up (2026-11-02)

- Body-backed metadata lengths are now compared with the fully verified file
  size for selected rows only. The version-1 producer has always exported full
  lengths from the exchange table, and record/spill use the same full bytes.
  A public-API probe previously accepted a 15-byte body with RespLen=0 and Get
  displayed the wrong length. Genuine zero-byte blobs with length zero remain
  valid; inline and legacy HTTP-head rows are unchanged.
- Re-importing existing rows no longer hashes their unlisted references. A
  concurrent deletion or a body created after a missing-file preflight requires
  an explicit retry, which re-verifies outside the lock. Tests prove the first
  attempt commits no rows and a subsequent retry succeeds.
- Review reproduced that SQL rollback did not remove newly published listed blobs.
  This predates reference validation and remains an explicit limitation, not a
  claim of filesystem transactionality. A synthetic failed-restore probe left
  zero rows and a complete blob; DeleteAll subsequently reclaimed it through
  the existing GC. Immediate cleanup is not guaranteed. Blind manifest-based
  deletion would risk shared or legacy evidence and is not introduced here.
  The targeted rollback cleanup below supersedes this observed limitation.

### Targeted failed-import cleanup

A failed import now tracks only canonical files it actually created. While still
holding the writer mutex, it requires a confirmed SQL rollback before cleanup;
a failed Commit followed by ambiguous ErrTxDone retains the files and reports
the uncertainty. Before deleting any candidate it collects all blob_refs and
legacy pointers, then checks the candidate's exact verified identity. Existing
files, live references, changed identities and uncertain query/legacy-read
results are retained. Only this import's unreferenced new files are removed;
there is no global sweep, and no promise of power-loss/filesystem transactionality.
The existing GC keeps its best-effort legacy-reader behavior; rollback cleanup
uses a strict variant so unreadable legacy evidence cannot justify deletion.
Tests cover late reference failure, an earlier source-loop failure, preserved
preexisting orphans and live/legacy bodies, and query/identity/legacy-path
uncertainty with explicit errors and retained bytes.
A deferred SQLite foreign-key fixture also forces Commit failure: the ambiguous
rollback is reported and the new blob remains intact. Panic transaction release
was statically reviewed (retErr=nil still rolls back an open transaction); no
runtime panic after Begin was injected. Strict legacy scanning rejects symlinks
rather than following paths outside the store, retaining uncertain new files.

Cubic follow-up tightens strict legacy collection: only regular request/response
files are read, so FIFO/socket/device entries fail closed instead of blocking
the writer mutex. The Linux FIFO fixture executes and returns promptly; Windows
does not support this fixture. Store-owned top-level _blobs/_index/_ca entries
are excluded before symlink checks and are never traversed. Ordinary legacy
symlinks remain errors. The former read-failure fixture is accurately named as
a symlink rejection; the generic read-error branch is statically reviewed, not
claimed as a separately induced runtime failure.

The legacy collector resolves the configured traffic root before walking: an
Open path that is a directory symlink (including a trailing separator) continues
to find legacy references. Only store-owned top-level trees are excluded;
underscore-prefixed URL directories inside a host tree are traversed. Regression
fixtures first demonstrated lost live blobs in GC and targeted cleanup, then
passed after this shared collector correction. Interior symlinks remain rejected
by strict cleanup, not followed. Ordinary GC still excludes _delete_staging.
Strict cleanup instead requires staging to be a readable, empty directory (or
absent) before collecting references. Nonempty, unreadable or symlinked staging
has unknown recovery state, so new blobs are retained with an error rather than
interpreting pending deletion journals. No recovery state machine was changed.
