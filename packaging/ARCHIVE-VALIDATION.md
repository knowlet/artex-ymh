# Bounded first-pass tar validation

## Scope and evidence (2026-10-22)

Repair PR #2 at `c0bcd0dc30b00b60e73b52854b14b0866a49d642`:
`verify_archive()` currently calls `list(archive)` before the member limits in
`extract_selected()` can reject an archive. The existing 28 offline tests pass
on Python 3.12.14 and do not distinguish early rejection from a second-pass
failure. The tools-bundle workflow uses Python 3.12.

The isolated checkout started clean on `ci/package-tools-bundle`; the PR base
was `3de6a1eeaec220d7763f167c1f89e77e411756c3`. The review finding is
[discussion_r4333438846](https://github.com/knowlet/artex-ymh/pull/2#discussion_r4333438846).

## Upstream comparison and decision

A targeted GitHub code search in `python/cpython` for `tarfile members append`
located the implementation and documentation. The implementation was then
checked at the fixed Python 3.12 commit below, rather than relying on the
search result's default branch.

| Candidate | Relevant behavior | Decision |
| --- | --- | --- |
| Existing Python 3.12 `tarfile`, `r:gz` | `TarFile.next()` retains each parsed `TarInfo` in `members`. | Keep the standard library and reject during the first traversal. |
| Python 3.12 `tarfile`, `r\|gz` | Stream I/O still retains member metadata. | Changing the open mode alone does not repair the defect. |

Source: [CPython `Lib/tarfile.py`, `next()` and `__iter__()`](https://github.com/python/cpython/blob/bb130d8a075f3b8171d1bb27a1313d060c462c96/Lib/tarfile.py).
Its [LICENSE](https://github.com/python/cpython/blob/bb130d8a075f3b8171d1bb27a1313d060c462c96/LICENSE)
identifies PSF License Version 2. This change directly uses the existing
standard-library dependency; no upstream implementation is copied or vendored.

Use one member validator for the initial verification scan and selected-file
extraction. Check count, negative sizes, safe and unique paths, allowed member
types, and cumulative declared file size before retaining metadata or reading
file contents. Reject sparse members even when unselected. During verification,
also reject non-file members and paths outside `data/tools/` immediately.
Only validated names and modes need to be collected; no additional list of
`TarInfo` objects is needed. Stopping at `MAX_MEMBERS + 1` bounds Python 3.12's
member cache for this attack. Limits remain inclusive at their exact boundary.

This is a logical-member limit, not a claim that all tar parser resource risks
are eliminated. PAX/GNU extension headers are processed inside `tarfile` before
a member is returned. ZIP central-directory allocation is a separate boundary.
Neither parser is replaced in this repair.

## Verification

- Use real compressed tar fixtures, including many empty files, oversized
  declared payloads, cumulative overflow, and malformed member metadata.
- Observe the real parser and fail if it reads another header after the member
  that must be rejected. Verification must fail before its extraction pass.
- Exercise extraction with unselected invalid members and retain positive
  tests at the exact count and size limits.
- Run the offline regression suite and manifest validation. Check the new PR
  head's CI for actual upstream downloads, two identical builds, archive
  verification, and artifact upload.
- A successful PR artifact build does not validate the signed tag Release
  workflow or deployment/runtime tool compatibility.

Local validation on Python 3.12.14:

| Check | Result |
| --- | --- |
| Original 28 tests before the change | Passed, exit 0. |
| `python3 -m unittest discover -s scripts -p test_build_tools_bundle.py -v` after the change | 35 tests passed, exit 0. |
| Same 35 tests against the original implementation loaded from the original PR head, in the same runtime | Expected failures: 14 failing subtests and 1 error across 6 new negative test methods; the original 28 and the new positive boundary test still pass. |
| `python3 scripts/build_tools_bundle.py --validate` | 14 bundled tools and 3 explicitly external tools, exit 0. |
| `git diff --check` | Passed, exit 0. |

The count fixture contains 10,002 real empty members and uses the production
limit of 10,000. Both entry points stop at member 10,001; the parser sentinel
fails if member 10,002 is requested. An oversized-header fixture declares more
than 1 GiB without supplying that payload, proving size rejection precedes
reading or skipping it. Other fixtures cover cumulative size, a global PAX
negative size, invalid paths, duplicates, links, devices, sparse entries, and
the verification-only bundle constraints. A complete valid bundle passes with
its count and content size exactly equal to the configured limits.

Independent review found no blocking implementation or regression-test issues.
The new PR head's upstream-download/build/artifact CI must still be checked;
its run URL and result belong in the PR validation record. The prior successful
run (39550829172) produced bundle SHA-256
`84023f8e3720123c6f0ba033d4e6142f6502b0470e272324c9146c5c907feadd`
for comparison; it is not evidence that the repaired head has passed CI.
