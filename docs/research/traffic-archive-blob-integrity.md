# Traffic archive blob integrity

## Decision (2026-10-26, before implementation)

- Base: `knowlet/artex-ymh` main `2181c4f776f2ea27dfb20cc9a35a7e7139b43634`.
- Scope: reject damaged existing destination blobs and complete new archive blob
  writes before publishing their canonical names. Preserve archive format, current-row-wins semantics, idempotency,
  and existing file modes. No scanning, target access, new dependencies, or changes
  to skill visibility, authentication, or archive reference coverage.
- Defect: `traffic/archive.go:ImportArchive` checks the incoming blob's SHA-256,
  but accepts an existing destination on `os.Stat` alone. A partial prior write
  can therefore be accepted on retry and followed by committed exchange metadata.
  Direct writes to the final blob name also expose partial output after failure.
- Existing coverage: `TestTrafficArchiveRoundTripAndCurrentRowWins` exercises
  inline bodies, not interrupted or corrupted blob restoration.

## Reference evidence and adoption

| Reference | Mechanism | Decision |
| --- | --- | --- |
| [in-toto `runlib.py`, `in_toto_match_products`](https://github.com/in-toto/in-toto/blob/e352b43ad7cb8915d84c36d791aa61346152a0a3/in_toto/runlib.py#L1060-L1097) | Recompute actual artifact hashes before comparing recorded products. | Reference design only; apply actual-byte verification to existing blobs. |
| [in-toto `verifylib.py`](https://github.com/in-toto/in-toto/blob/e352b43ad7cb8915d84c36d791aa61346152a0a3/in_toto/verifylib.py#L748-L763) | Require both destination existence and matching hashes. | Reference design only; existence is not integrity evidence. |
| ARTEX `evidence/store.go:writeBody` | Write a temporary file, synchronize and close it before publishing. | Reuse the repository's staging pattern; do not change the separate evidence store. |

The pinned in-toto source uses [Apache-2.0](https://github.com/in-toto/in-toto/blob/e352b43ad7cb8915d84c36d791aa61346152a0a3/LICENSE).
No source is copied or translated and no in-toto dependency is introduced. Its
signed supply-chain metadata and rule engine are not needed for this local
traffic-archive correctness fix. The ARTEX repository remains AGPL-3.0.

## Acceptance and verification plan

1. First run a regression against the unchanged implementation: a valid incoming
   blob plus a truncated or same-length-corrupt destination must not be reported
   as a successful import.
2. After the fix, reject bad existing bytes without replacing them or committing
   exchange rows. Propagate filesystem errors instead of silently accepting them.
3. Reuse valid existing bytes, preserve current exchange rows, and keep valid
   repeated restores idempotent.
4. A new blob becomes visible only after a complete, synchronized write; a
   mid-copy failure removes staging output and leaves no final blob.
5. Run the traffic package tests, race detector, vet, and build in the assistant's
   cloud workspace with synthetic fixtures and no external scan targets.

Testing outcomes are recorded separately; these acceptance statements are not
claims that tests have already passed. Power-loss simulation and whole-platform
integration require separate evidence and are not claimed by unit tests.

## Publication and filesystem boundaries

- New bytes are staged on the destination filesystem, synchronized, closed, and
  published with `os.Rename`, following ARTEX's existing evidence-store pattern.
  A final destination recheck rejects or verifies an already-observed file before
  publication. The existing `Traffic.wmu` serializes the supported in-process
  capture, import, and garbage-collection writers.
- This is not an atomic no-clobber guarantee against unrelated processes or an
  adversary changing paths between the final check and rename. Sharing a data
  tree with such writers is outside this change's contract.
- A preliminary implementation used `os.Link` for atomic no-clobber publication.
  Review identified a new hard-link filesystem requirement (e.g. FAT/exFAT and
  some shares). It was replaced before release to preserve the existing
  filesystem compatibility contract; direct writes to final files were not
  restored as a fallback.
- Normal returned copy failures remove staging output. Process termination or a
  cleanup filesystem error may leave a private `.archive-blob-*` directory; the
  existing blob garbage collector can reclaim unreferenced staging output.
  The parent directory is not synchronized, so this change does not claim
  complete power-loss durability. Filesystems also retain their native rename
  semantics: Go does not guarantee atomic `os.Rename` on non-Unix platforms,
  even within one directory. The portable guarantee is complete write/Sync/Close
  before publication, with copy failures leaving no canonical partial file.
  Unit tests validate the assistant's Linux filesystem, not every supported
  deployment platform.

## Local verification (2026-10-26)

Executed in an isolated assistant-owned Linux/amd64 cloud checkout, using the
already-installed Go 1.27.2 toolchain and workspace-local module/build caches.
`go.mod` declares Go 1.26.3; exact-version CI remains a separate check. All test
inputs are temporary synthetic data or loopback fixtures, not scan targets or
paid LLM calls.

| Check | Result |
| --- | --- |
| Unchanged base plus corruption regression | Expected failure: all three empty/truncated/same-length-corrupt destination cases incorrectly returned `imported=1, err=nil`. |
| Pristine base, `go test -p=2 -count=1 -json -timeout=120s ./traffic` | 50 top-level tests passed (54 including subtests), zero failures/skips. |
| Final change, same full traffic command | 56 top-level tests passed (69 including subtests), zero failures/skips. |
| `go test -race -p=2 -count=1 -json -timeout=180s ./traffic` | 56 top-level tests passed (69 including subtests), zero failures/skips. |
| `go vet -p=2 ./traffic` | Passed. |
| `go build -p=2 ./traffic` | Passed; this is the affected package build, not a complete frontend/deployment build. |
| `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -p=2 ./traffic` | Passed cross-compilation only; the Windows test binary was not executed. |
| `git diff --check` | Passed. |

The regression tests also cover valid reuse, repeated restoration, corrupt
incoming bytes, non-regular destinations, returned copy failures and retry, and
the destination recheck before publication. A Windows symlink fixture is skipped
only for explicit privilege/unsupported-filesystem errors; the Linux run skipped
nothing. Whole-platform PostgreSQL integration, Windows filesystem runtime,
process-kill/power-loss behavior, and production deployment were not tested here.
