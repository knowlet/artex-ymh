# Provider integration evidence (2026-10-24)

Base: knowlet/artex-ymh main `5cddfce1fd7de9ffde26bacbf5e6366b49019492`.
No applicable AGENTS.md or .agents skills were found in the workspace or repository.
The original work checkout is clean and is preserved; implementation uses an isolated worktree.
Existing Draft PR #5 vendors original playbooks and is outside this implementation.

| Reference | Evidence and decision |
| --- | --- |
| [Claude-Red pinned tree](https://github.com/SnailSploit/Claude-Red/tree/a8de813edc9f66f60d44cfe42d47750e89d9930b) | Fixed revision, 79 skill documents in 23 categories. Catalog hashes exact source bytes; no skill text is vendored. Root MIT alone does not establish inherited document provenance. All entries stay metadata-only/provenance-unverified. |
| [Norma loader v0.4.3](https://github.com/Autumn-27/norma/blob/v0.4.3/skill/skill.go) | Existing dependency, directly reused. LoadDir scans one level, tolerates malformed frontmatter and Registry.Add replaces duplicate display names. Provider validation must be stricter. Generated names match directory names. MCP frontmatter must not become active. |
| [ARTEX assembly](https://github.com/knowlet/artex-ymh/blob/5cddfce1fd7de9ffde26bacbf5e6366b49019492/server/assembly.go) | Existing per-run DB visibility filter and metered Skill invocation are retained. Import does not write bindings, tools or MCP configuration. Revocation applies to freshly assembled runs. |
| [ARTEX ZIP upload](https://github.com/knowlet/artex-ymh/blob/5cddfce1fd7de9ffde26bacbf5e6366b49019492/server/server_mgmt.go) | Single-skill upload, not a provider batch importer. Do not repurpose it or weaken its controls. |
| [Agent Skills specification](https://github.com/agentskills/agentskills) | Official specification repository discovered with GitHub search `agentskills specification`; useful format context only. Actual compatibility is tested against pinned Norma, rather than assuming specification compliance. |

Searches used connected GitHub repo search for format specifications and symbol search `LoadDir` in Autumn-27/norma. Source review covered loader, registry, ARTEX assembly, upload and usage ledger. No upstream programs, converters or installation scripts were executed.

## Implementation decision

Extend ARTEX with an original Go provider package and an offline administration command. Validate a versioned catalog, explicit source revision, byte counts, SHA-256, namespace, dependencies and provenance. Convert only explicitly selected, provenance-verified and import-allowed documents. Keep exact original source and license as inert references; generate only safe name/description/license frontmatter. Publish the entire new library with one no-replace rename. Existing destinations are refused, so atomicity never overwrites user modifications. Operators choose the library through the existing ARTEX_SKILL_DIR setting and grant visibility through existing controls. This first foundation deliberately does not merge libraries in place.

Readiness reports metadata, receipt-verified import, current visibility evidence, registration evidence, binary/hash evidence and runtime evidence independently. A tool mention or alias cannot prove installation or execution. Offline status has no DB or executable access and reports unavailable evidence as unknown.

## Acceptance

Use harmless original fixtures for modern/legacy conversion, real Norma LoadDir and Skill invocation, hostile filesystem/format/hash/limit inputs, cancellation, no-replace publication and missing/tampered receipt evidence. Real PostgreSQL tests exercise opt-in visibility, revocation on a fresh run and hit/miss usage attribution; these must be explicitly reported as unverified if the database cannot run. Provider source must not import subprocess or network packages. No third-party attack-tool runtime acceptance is claimed.
