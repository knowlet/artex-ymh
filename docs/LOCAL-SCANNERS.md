# Managed local OSV / Trivy scanners — first integration slice

Stacked follow-up to #10, not a replacement intelligence/source updater. Pins:
**OSV-Scanner v2.7.0**, **Trivy v0.76.1**, Linux amd64. The original refresh,
ProjectDiscovery bundle, installer, discovery runner and server permissions are
unchanged. Installation fails if these reviewed pins drift from #10's registry;
a registry refresh cannot silently upgrade this execution lane.

## Implemented scope versus source records

| Tool | Implemented in this change | Not enabled |
| --- | --- | --- |
| OSV-Scanner | Verified installation, managed CLI, JSON findings, offline Go SBOM matching | Source trees, remote repos, commit scans, call analysis, fix |
| Trivy | Verified installation, same CLI/result contract, offline Go SBOM matching | Remote images, Docker socket, filesystem/IaC/secret scans, Java DB, VEX, plugins |
| ZAP | Source registry only | Baseline/spider/active scanning; crawling still generates target requests |
| ffuf | Source registry only | Fuzzing and enumeration; request volume/mutations depend on inputs |
| PHP2Shell | Source registry only | Intrusive probes that can exhaust memory or interrupt service |

This is an **operator CLI capability**, not automatic agent/server/UI integration.
No endpoint, scheduled scan, deployment, permission change or production DB
mutation. Local account access plus `--authorized` gates each run; this is an
acknowledgement, **not server RBAC or proof of target authorization**. Existing
generic shell privileges are neither narrowed nor expanded.

## Host prerequisites and trust

Linux amd64, trusted `/usr/bin/python3` 3.10+, `/usr/bin/bwrap`, and
`/usr/bin/prlimit`; unprivileged user/network namespaces must be available.
ARTEX embeds the stdlib-only Python worker and reviewed source lock, invokes
Python with `-I` and a minimal environment, before service initialization.

Missing helpers, unsupported ELF, denied namespaces, missing/corrupt/stale DB,
invalid output or partial package coverage fail closed. **No online or
unsandboxed fallback.** Only static amd64 ELF binaries are accepted. Bubblewrap
uses new namespaces, drops capabilities and mounts only the private scanner,
sanitized SBOM and copied DB read-only, plus private `/proc`, `/dev`, `/tmp`
and empty home. No host network, host filesystem, Docker socket, credentials,
user-supplied flags, scanner config or arbitrary commands are passed through.

The host interpreter/helpers, installation, current OS account and kernel are
trusted. Installation files may not be group/world writable. This does not
protect against a malicious same-UID process, compromised helpers or kernel.
Hashes detect changed bytes; they are not signatures. No Sigstore/SLSA
verification or bit-reproducible upstream compilation is claimed. Reproducible
here means identical reviewed release inputs produce identical add-on tar bytes.

## Build/install, separate from scanning

From this checkout on a connected preparation machine, choose absent outputs:

```sh
python3 scripts/install_local_scanners.py --cache /absolute/source-cache --validate
python3 scripts/install_local_scanners.py --download \
  --cache /absolute/source-cache \
  --bundle /absolute/local-scanners.tar.gz \
  --install-dir /absolute/managed-scanners
```

This reuses `build_tools_bundle.py` for bounded archive parsing, validation,
license retention and deterministic tar construction. OSV is a raw executable;
Trivy is a selected member of tar.gz. Both official release asset SHA-256 and
SHA-256-pinned checksum lists are verified. Apache-2.0 license text comes from
exact commits and is verified against Git blob identities. No token is passed
to downloads; every source is enumerated in `localscan/sources.lock.json`.

Installation is a **new separate directory** and never overwrites `data/tools`,
its manifest, an existing installation or a production binary. For offline
installation, transfer the source cache plus this reviewed checkout, omit
`--download`, and choose a new destination. Missing/corrupt cache fails without
implicit downloads. The add-on tar is an inspectable distribution artifact,
not a self-authenticating installer. A standalone imported-tar installation
command is **not implemented**; do not blindly extract it into production.

## Prepare vulnerability databases separately

Scanning never downloads/updates DBs. Prepare each snapshot in a new directory:

* OSV: official Go ecosystem `all.zip` at
  **`DB_ROOT/osv-scalibr/Go/all.zip`**. The pinned scanner uses the Scalibr cache
  layout, not older `osv-scanner/Go` examples. Managed execution sets
  `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db` and mounts the snapshot there.
* Trivy: the verified binary's explicit preparation command:
  `trivy image --download-db-only --cache-dir DB_ROOT --skip-version-check --disable-telemetry`.
  No target image is supplied; only the vulnerability database is downloaded.

Then bind the prepared bytes to an operator-supplied source and actual timestamp:

```sh
artex scan seal-db --tool osv-scanner --db-dir /absolute/osv-db \
  --source 'https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip' \
  --retrieved-at 'ACTUAL_RFC3339_RETRIEVAL_TIME'
artex scan seal-db --tool trivy --db-dir /absolute/trivy-db \
  --source 'ACTUAL_DB_SOURCE_AND_DIGEST_OR_PREPARATION_LOG_REFERENCE' \
  --retrieved-at 'ACTUAL_RFC3339_RETRIEVAL_TIME'
```

`seal-db` never accesses the network and never overwrites an existing receipt.
Source/time assertions are **operator-attested, not independently authenticated**.
Hashes bind bytes, not the truth of the supplied source/time. Receipt age is at
most seven days; Trivy DB schema must be 2 and `UpdatedAt` within seven days.
Old OSV bytes resealed with a new time cannot be independently detected in this
slice; retain trustworthy preparation records.

Only required DB files are hashed, size-bounded and copied to a private snapshot.
Unexpected extras are not mounted. Sealing/copying uses at most 1 MiB blocks,
not whole-file buffers. Changed/truncated files and failed copies remove staged
files and fail. Same-UID adversarial filesystem races remain outside the threat
model. DB metadata is read from the verified private snapshot.

## Plan/run and input contract

Supported input is CycloneDX JSON 1.4–1.6, **1–5,000 flat Go library components**,
with matching name, semantic version and canonical `pkg:golang/...@version`.
No qualifiers, ambiguous versions, nested components or other ecosystems.
Input limit is 8 MiB. External references, metadata commands, VEX/config fields
and unrelated input are removed from the canonical staged SBOM. This is not a
claim of complete scanning for arbitrary CycloneDX documents.

```sh
artex scan plan --tool osv-scanner --install-dir /absolute/managed-scanners \
  --sbom /absolute/bom.json --db-dir /absolute/osv-db
artex scan run --tool osv-scanner --install-dir /absolute/managed-scanners \
  --sbom /absolute/bom.json --db-dir /absolute/osv-db \
  --authorized --report-dir /absolute/new-osv-report
# For Trivy select --tool trivy and its own prepared DB root.
```

Plan validates binary and DB bytes but executes no scanner. Run authorization is
checked before expensive preflight. Each run requires a new report directory.
A `running`, `complete:false` receipt precedes dispatch. Native stdout/stderr
and a final normalized result are retained. Kill/host failure can leave an
incomplete receipt; existence of a report is never proof of successful scanning.

## Result and exit contract

Schema 1 includes `status`, `complete`, `plan`, native exit code/output hash and
findings. Plans bind version/commit, binary hash, original/canonical input hashes,
DB receipt/source/time/file hashes, fixed argv, coverage scope and limits.
Findings retain package/version/ecosystem, advisory ID, aliases, fixed versions
and reported severity. IDs sharing a CVE alias are not deduplicated into a
unique-CVE count. Matching is **not proof of exploitability**.

| ARTEX exit | Result | Meaning |
| --- | --- | --- |
| 0 | no_findings, complete true | Every supported input identity appeared; this DB snapshot matched no advisory |
| 1 | findings, complete true | Matching completed with one or more advisories |
| 2 | failed, complete false | Validation, authorization, sandbox, DB, execution, output or coverage failed |

Plan/seal-db also return zero for successful non-scan operations. Native OSV
exit 1 is accepted only with valid findings; zero must agree with no findings.
**Nonempty native OSV errors fail even when results and exit code look valid.**
Trivy uses native `--exit-code 0`; nonzero is failure. Empty/malformed/truncated
JSON, duplicate keys, wrong schema, missing package inventory and partial
coverage cannot become a clean scan. Preflight errors emit failed JSON without
scanner dispatch. Callers must require complete true and a completed status.

## Resource envelope

Per scan: default wall **120 s** (`--timeout` **1–300**), CPU **120 s**, address space **8 GiB**,
per-file **64 MiB**, file descriptors **128**, stdout **16 MiB**, stderr **1 MiB**. Limit violations
kill/reap the process group. Go gets `GOMAXPROCS=2` and soft `GOMEMLIMIT=768 MiB`.
DB snapshot aggregate **4 GiB**, DB metadata **1 MiB**, binary **256 MiB**. DB copies are streamed
in **1 MiB** blocks. The actual Trivy DB exceeded the original **1 GiB** design limit;
real acceptance exposed that problem and the bounded streaming path replaces it.

Address-space is **not RSS**, and GOMEMLIMIT is soft. No aggregate scratch-space,
host-wide concurrency or cgroup quota is supplied. Use an independently
resource-constrained job/container where those guarantees are required. This
PR does not install a service or assert a full hostile-code sandbox guarantee.

## Verification

```sh
python3 -m unittest discover -s localscan -p 'test_*.py' -v
go test -race ./localscan
go vet ./localscan
go build -o /tmp/artex-local-scan ./cmd/artex
```

The read-only PR workflow additionally runs existing bundle regressions,
installs actual official pinned binaries, records versions/help, compares two
bundle hashes (second build offline from cache), prepares actual DBs separately,
and scans authored local Go SBOMs through the network-disabled runner. Expected
cases include a known gogo/protobuf advisory, a synthetic no-advisory package,
authorization denial, and corrupt/missing DB rejection. Tests include process
timeout/output/environment limits, DB streaming/cleanup, and native-error handling.

**The existence of the workflow is not a pass claim.** Inspect the exact-head
Actions result and `local-scanner-evidence-*` artifact; skipped/failed checks do
not establish integration. Evidence includes native JSON, diagnostics, install
pins, DB receipts/sizes and test logs, including on failure. External DB download
or rate-limit failure is a failed preparation, never a clean scan. The synthetic
no-advisory package does not establish that an actual package exists or is safe.

Official references:
- https://google.github.io/osv-scanner/usage/offline-mode/
- https://google.github.io/osv-scanner/output/
- https://github.com/google/osv-scanner/issues/2983
- https://trivy.dev/docs/latest/advanced/air-gap/

Rollback: revert this child PR or remove its separate installation. #10's source
refresh, existing tools, deployments, permissions and production DBs are untouched.
