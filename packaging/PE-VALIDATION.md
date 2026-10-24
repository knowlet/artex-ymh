# Pinned PE architecture validation

## Scope and evidence (2026-10-22)

Repair [PR #2, discussion_r4343818908](https://github.com/knowlet/artex-ymh/pull/2#discussion_r4343818908)
at `f34f85e19cf12144c6291b9c7d8739446643602a`. The isolated checkout started
clean, with base `3de6a1eeaec220d7763f167c1f89e77e411756c3`. No applicable
`AGENTS.md` or repository-local agent skills were present.

The existing `pe` check reads the DOS and PE signatures but not the COFF
`Machine` field. All 35 existing offline tests pass on Python 3.12.14, including
a PE fixture with a zero machine value. A direct baseline check also accepts
x86 (`0x014c`), ARM64 (`0xaa64`), and PE signatures with truncated COFF headers.

## Reference and decision

A targeted public search for Go's PE reader located `debug/pe.NewFile`.
Read [its implementation at fc8da86](https://github.com/golang/go/blob/fc8da86d21f0ab363b53b18d8f256b4dd664eb53/src/debug/pe/file.go)
and the [BSD-style license](https://github.com/golang/go/blob/fc8da86d21f0ab363b53b18d8f256b4dd664eb53/LICENSE).
It reads a little-endian COFF file header immediately after the PE signature,
then inspects `Machine`. Its general-purpose reader accepts multiple machines,
including unknown; that policy is too broad for an architecture-pinned bundle.
Only the parsing principle is referenced; no Go code is copied or vendored.

The [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image)
defines the 20-byte COFF header and its leading two-byte `Machine` field.
The documented amd64 value is `0x8664`. Keep the existing Python standard-library
implementation rather than add a general PE parser dependency. Replace `pe`
with explicit `pe-amd64`, require the PE signature and complete COFF header to
lie after the DOS header and within the input, and compare `Machine` exactly.
The shared check applies during both building and independent verification.
This is architecture/header validation, not full Windows loader validation.

## Checked inputs

All three exact pinned assets were downloaded and their complete required
SHA-256 checked before static header inspection. No downloaded tool was run.

| Output | SHA-256 | Machine | PE offset |
| --- | --- | --- | --- |
| `mimikatz.exe` | `61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1` | `0x8664` | 288 |
| `laZagne.exe` | `dc06d62ee95062e714f2566c95b8edaabfd387023b1bf98a09078b84007d5268` | `0x8664` | 248 |
| `peass/winPEASx64.exe` | `f8dea041a0ba3359b3a7a79431248f1e585f795758e91b7c422b5a939fd99135` | `0x8664` | 128 |

Sources are the exact release URLs already in `tools-sources.lock.json`:
[Mimikatz 2.2.0-20220919](https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip)
(`x64/mimikatz.exe`, selected-file pin),
[LaZagne v2.4.7](https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe),
and [winPEAS 20261019-18cc21b4](https://github.com/peass-ng/PEASS-ng/releases/download/20261019-18cc21b4/winPEASx64.exe).
In particular, this pinned LaZagne is amd64, not x86. No URLs, versions, hashes,
tool payloads, or original runtime-manifest entries need to change.

## Verification

- Preserve the tar early-rejection regression coverage and existing behavior.
- Cover accepted amd64, rejected x86/ARM64/zero/unknown values, malformed DOS/PE
  headers, every incomplete COFF-header length, and offset bounds.
- Exercise the lock-selected check through both build and archive verification,
  with matching hashes so that digest failures cannot mask the machine check.
- Compare the new negative integration regression against the original code and
  original lock in the same Python runtime, then run the complete offline suite,
  manifest validation, compile check, and whitespace check on the repair.
- Actual upstream bundle builds and new-head CI are separate from these static
  and offline checks. No application, scanner, listener, or downloaded tool is
  executed; runtime compatibility and signed releases remain untested.

Executed locally on Python 3.12.14:

| Check | Result |
| --- | --- |
| Original suite at `f34f85e` | All 35 tests passed, exit 0. |
| New `test_pe_architecture_rejected_by_build_and_verification` with original implementation and original lock | Expected exit 1: 10 failing subtests (five bad inputs through both entry points), all because `BundleError` was not raised. The amd64 positive case passed. |
| `python3 -m unittest discover -s scripts -p test_build_tools_bundle.py -v` on the repair | All 39 tests passed, exit 0, including the same integration regression and all existing tar tests. |
| `python3 scripts/build_tools_bundle.py --validate` | 14 bundled / 3 explicitly external, exit 0. |
| `python3 -m py_compile scripts/build_tools_bundle.py scripts/test_build_tools_bundle.py` | Passed, exit 0. |
| Recheck all three cached, hash-verified upstream EXEs through the repaired `check_format` | All passed `pe-amd64`; no tool execution. |
| `git diff --check` | Passed, exit 0. |

The original implementation and lock were read from the exact parent commit
into a separate temporary directory; the new integration test was copied there
unchanged. It selects the check from that lock, so the baseline failure is not
an artificial rejection of the newly introduced `pe-amd64` label.
