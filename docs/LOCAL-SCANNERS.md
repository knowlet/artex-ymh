# Managed local OSV / Trivy scanners — first integration slice

This is a **stacked follow-up to #10**, not a replacement source updater. The
reviewed pins are OSV-Scanner **v2.7.0** and Trivy **v0.76.1**, Linux amd64. The
original intelligence refresh, ProjectDiscovery bundle, installer, runner and
server permissions are unchanged. Install-time pin drift against #10's registry
fails closed; a registry refresh does not silently upgrade this execution lane.

## Implemented scope versus source records

| Tool | In this change | Not enabled |
| --- | --- | --- |
| OSV-Scanner | Source/hash/license-verified installation; `artex scan plan/run`; JSON findings; local offline Go SBOM matching | Source-tree scanning, remote repositories, commit scans, call analysis, `fix` |
| Trivy | Source/hash/license-verified installation; same managed CLI/result contract; local offline Go SBOM matching | Remote images/registries, Docker socket, filesystem/IaC/secret scans, Java DB, VEX, plugins |
| ZAP | Source registry only | Spider/baseline/active scans: even a nominally passive workflow may crawl and generate target requests |
| ffuf | Source registry only | Fuzzing/wordlist enumeration: request volume and mutation depend on flags and inputs |
| PHP2Shell | Source registry only | Intrusive probes that can exhaust memory or interrupt service; no imported PoCs/templates |

No scanner is automatically registered with agents or the HTTP API. This is an
**operator CLI capability**, gated by local account access and an explicit
`--authorized` acknowledgement for each run. That acknowledgement is not remote
authorization discovery or server RBAC. Existing generic shell privileges are
not narrowed or broadened. No new server endpoint, scheduled scan, merge,
production deployment, database mutation or automatic tool activation occurs.

## Host prerequisites and trust

Linux amd64; trusted `/usr/bin/python3` (3.10+), `/usr/bin/bwrap`, and
`/usr/bin/prlimit`; unprivileged user/network namespaces must be allowed. The
ARTEX binary embeds the Python worker and reviewed lock; Python runs with `-I`
and a minimal environment. Missing helpers, unsupported ELF, denied namespaces,
missing/corrupt/stale DB, bad output and partial package coverage all fail closed.
There is **no unsandboxed or online fallback**. The minimal sandbox accepts
static ELF binaries only, mounts only the copied scanner, sanitized SBOM and
private DB snapshot read-only, and exposes private `/proc`, `/dev`, `/tmp` and
an empty home. It has a new network namespace and no host filesystem/socket
mount. CLI flags are fixed; arbitrary arguments/configuration are not accepted.

The host interpreter/helpers, installation and current OS account are trusted.
Installation files cannot be group/world writable. This is not protection
against a malicious same-UID process, compromised dependencies, or kernel.
Binary/license hashes detect changed installed bytes but are not code signatures.
No SLSA/Sigstore attestation verification or bit-reproducible upstream compilation
is claimed. **Reproducibility here means packaging identical pinned source
artifacts into identical add-on tar bytes.**

## Build and install (explicitly separated from scanning)

Run from this PR's checkout on a connected preparation machine:

```sh
python3 scripts/install_local_scanners.py --cache /absolute/source-cache --validate
python3 scripts/install_local_scanners.py --download \
  --cache /absolute/source-cache \
  --bundle /absolute/local-scanners.tar.gz \
  --install-dir /absolute/managed-scanners
```

Both output paths must be absent. Installation is in a **separate directory**;
it does not replace `data/tools`, its manifest, or a production binary. The
existing generic `build_tools_bundle.py` is reused for bounded archive parsing,
format checks, source verification, license retention and deterministic tar.
OSV is a raw executable; Trivy is a tar.gz selected member. Release asset SHA-256
and SHA-256-pinned checksum lists are both checked. Apache-2.0 notices are fetched
from the exact source commits and verified against their Git blob identities.
No token is passed to source downloads. Every input is explicitly enumerated in
`localscan/sources.lock.json`; no latest-version discovery is performed here.

For offline installation, transfer the **source cache plus this reviewed
checkout**, omit `--download`, and choose a new destination. Missing or altered
cached inputs fail; there is no implicit download. The add-on tar is an
inspectable distribution artifact, not a self-authenticating installer. A
standalone imported-tar installation command is **not implemented**. Do not
blindly extract a downloaded tar into a production tools directory.

## Prepare vulnerability databases separately

Scanning never downloads or updates databases. Use a **new** DB directory for
each snapshot. On a connected preparation machine, manually obtain:

* OSV: official Go ecosystem `all.zip`, at
  `DB_ROOT/osv-scanner/Go/all.zip`.
* Trivy: use the verified installed binary's explicit preparation command:
  `trivy image --download-db-only --cache-dir DB_ROOT --skip-version-check`.
  No image target is supplied. This downloads a DB, not a target image.

Record the actual source and retrieval time, then seal the prepared bytes:

```sh
artex scan seal-db --tool osv-scanner --db-dir /absolute/osv-db \
  --source 'https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip' \
  --retrieved-at 'ACTUAL_RFC3339_RETRIEVAL_TIME'
artex scan seal-db --tool trivy --db-dir /absolute/trivy-db \
  --source 'ACTUAL_TRIVY_DB_SOURCE_AND_DIGEST_OR_PREPARATION_LOG_REFERENCE' \
  --retrieved-at 'ACTUAL_RFC3339_RETRIEVAL_TIME'
```

`seal-db` does not access the network. Its source/time assertion is
**operator-attested, not independently authenticated**; hashes bind the bytes,
not the truth of that assertion. Existing receipts are never overwritten.
Receipt age is limited to seven days; Trivy DB schema must be 2 and `UpdatedAt`
within seven days. A newly sealed old OSV DB cannot be detected from upstream
signature/freshness evidence in this slice; use trustworthy preparation records.
All required files are hashed, bounded and copied to a private snapshot before
execution. Extras in the source directory are not mounted. Rewriting a source
file with different bytes cannot pass its receipt digest. No concurrent hostile
same-account filesystem mutation guarantee is claimed.

## Plan and run

Supported input: CycloneDX JSON 1.4–1.6, **1–5,000 flat Go library components**,
each with matching name, semantic version and canonical `pkg:golang/...@version`.
No qualifiers, ambiguous versions, nested components or other ecosystems.
Input is at most 8 MiB. External references, metadata commands, VEX/config data
and unrelated fields are removed from the staged canonical SBOM. This is not a
claim that an arbitrary CycloneDX document is completely scanned.

```sh
artex scan plan --tool osv-scanner --install-dir /absolute/managed-scanners \
  --sbom /absolute/bom.json --db-dir /absolute/osv-db
artex scan run --tool osv-scanner --install-dir /absolute/managed-scanners \
  --sbom /absolute/bom.json --db-dir /absolute/osv-db \
  --authorized --report-dir /absolute/new-osv-report
# Use --tool trivy and its own DB root for the second implementation.
```

Planning validates installed bytes and DB snapshot but executes no tool. Each
run requires a new report directory. A persisted `running`/`complete:false`
receipt precedes dispatch. Native stdout/stderr and a final normalized receipt
are retained. Cancellation/kill can leave a `running` receipt: it is not success.

## Result contract / failure semantics

Schema 1 returns `status`, `complete`, `plan`, `native_exit_code`,
`native_sha256` and `findings`. The plan includes versions/source commit, binary
hash, original/canonical input hashes, DB manifest hash/source/time/file hashes,
fixed argv, coverage scope and effective limits. Findings retain package,
version, ecosystem, upstream advisory ID, aliases, fixed versions and reported
severity. Separate upstream advisory IDs may share a CVE alias: counts are not
unique-CVE counts. This is database matching, **not exploitability proof**.

| ARTEX exit | Result | Meaning |
| --- | --- | --- |
| 0 | `no_findings`, complete true | All explicitly supported input identities appeared in scanner output; no matching advisory in this DB snapshot |
| 1 | `findings`, complete true | Completed matching with at least one advisory |
| 2 | `failed`, complete false | Validation, permission, sandbox, execution, DB, schema, output-limit or coverage failure |

`plan`/`seal-db` also return zero on successful non-scan operations. OSV native
exit 1 is accepted **only** with valid nonempty findings; other error codes and
inconsistent result/exit combinations fail. Trivy uses native `--exit-code 0`;
nonzero is failure. Empty objects, truncated JSON, duplicate keys, wrong schema,
missing inventory and partial results cannot become a clean scan. Preflight
errors emit a failed JSON response without dispatch. Abrupt host-process death
may prevent a final report; callers must require complete true, not merely an
existing file or subprocess exit.

## Resource envelope

Each scan: default 120 s wall clock (explicit 1–300 s), hard CPU120 s,
address-space8 GiB, per-file64 MiB and file-descriptor128 limits. Stdout16 MiB,
stderr1 MiB; oversized output kills/reaps the process group. Go processes get
GOMAXPROCS2 and a soft GOMEMLIMIT768 MiB. DB snapshot max4 GiB total (metadata max1 MiB), binary max256 MiB.
DB sealing and snapshot copies stream in at most 1 MiB blocks; they do not load
the database into a single Python buffer. Changed/truncated files and partial
snapshot writes fail with staged files removed.
The address-space limit is **not** a hard RSS limit; the heap limit is soft.
There is no aggregate scratch-space, host-wide concurrency or cgroup quota.
Deploy this CLI in an already resource-constrained job/container where those
additional guarantees are required. This PR does not install a service.

## Verification and acceptance status

`python3 -m unittest discover -s localscan -p 'test_*.py' -v` covers parsing,
coverage/exit consistency, safety flags, DB/time/hash failure modes, installer
no-overwrite, process timeout/output limits and environment isolation.
`go test -race ./localscan` covers embedded pins, isolated worker dispatch,
help and rejected target arguments. Existing bundle tests remain unchanged.

`.github/workflows/local-scanners.yml` additionally builds the complete ARTEX
CLI, installs the real official pinned binaries, builds the bundle twice,
rebuilds from cache without downloads, records version/help, explicitly prepares
real DBs, and scans authored local SBOMs through the no-network runner. It expects
a known gogo/protobuf advisory and a no-advisory synthetic package, then checks
authorization denial and missing/corrupt DB failures. These are **acceptance
checks, not a claim they passed**: inspect the exact PR-head Actions run and its
`local-scanner-evidence-*` artifact. A skipped or failed acceptance job does not
establish real integration. DB downloads can fail independently due to registry
availability/rate limits; that is not a clean scan.

Official behavior references:
- https://google.github.io/osv-scanner/usage/offline-mode/
- https://google.github.io/osv-scanner/output/
- https://trivy.dev/docs/latest/advanced/air-gap/

Rollback: revert this child PR or remove its separate installation. No #10
source/CVE refresh, existing tool pin, deployment, permission or DB is modified.
