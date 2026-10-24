# Claude-Red source catalog

This directory contains source metadata, original neutral descriptions and a
curated dependency-name index. It contains no upstream skill text and is outside
ARTEX's loadable `skills/` directory. Catalog entries do not grant agent access
or register executable tools.

The snapshot is pinned to
[`a8de813edc9f66f60d44cfe42d47750e89d9930b`](https://github.com/SnailSploit/Claude-Red/tree/a8de813edc9f66f60d44cfe42d47750e89d9930b).
The fixed Git tree and all source bytes were checked on 2026-10-24:

| Observation | Verified value |
| --- | --- |
| Skill documents | 79 |
| Categories | 23 |
| Documents with YAML frontmatter | 51 |
| Legacy documents without YAML frontmatter | 28 |
| Documents containing an `offensive-checklist` source marker | 50 |
| Upstream manifest version | 0.3.0 |
| Upstream README/manifest claimed count | 78 (stale; tree contains 79) |

Each entry records the source-relative path, exact byte count, SHA-256 and
observed format. Source bytes were also checked against the pinned tree's Git
blob identities during catalog preparation. The catalog schema version is
independent of the upstream manifest version.

| Source metadata | SHA-256 |
| --- | --- |
| [Root LICENSE](https://github.com/SnailSploit/Claude-Red/blob/a8de813edc9f66f60d44cfe42d47750e89d9930b/LICENSE) | `f2ebf01e609ee09215fbe0334dc8a96e7474a186f07a73e24e983fa2462e0ff9` |
| [Upstream manifest](https://github.com/SnailSploit/Claude-Red/blob/a8de813edc9f66f60d44cfe42d47750e89d9930b/claude-skills.json) | `91a123006a8a43e59b5e0cb061f77a926b79f4de78b7c893518ce07d0be4687c` |
| [Upstream README](https://github.com/SnailSploit/Claude-Red/blob/a8de813edc9f66f60d44cfe42d47750e89d9930b/README.md) | `82bb9daa054e003caa6a4c33a2f19209cb5c711bcc65e34707b54828ef3698c3` |

## Provenance and import policy

The root license declares MIT. Several documents reference content from
[`SnailSploit/offensive-checklist`](https://github.com/SnailSploit/offensive-checklist),
whose source-content license was not verified for this integration. A root
license declaration alone does not settle the provenance of those documents.
All 79 entries are therefore conservatively marked `provenance-unverified` and
`metadata-only`. The importer rejects them. Their hashes provide identity and
integrity evidence; they do not certify licensing or approval to load content.

No upstream `SKILL.md`, installer, converter, binary, exploit, evasion,
persistence, exfiltration or lateral-movement implementation is included.
Selective importer verification uses original harmless fixtures. Any later
source-content approval needs its own provenance review and reviewed catalog
change; this snapshot does not authorize it.

## Dependency identifiers and readiness

`dependencies` maps canonical inventory IDs such as `tool-netexec` to documented
spellings such as `NetExec` and `nxc`. Skill entries reference those IDs. These
85 tool-family mappings cover known names observed in 72 source documents;
they are a curated, non-exhaustive index. An empty list means no mapping was
recorded, and does not establish that the document has no external requirements.
Aliases identify documentation names; they are not command templates, version
compatibility claims or proof that every function in a tool family is present.

Keep these observations separate:

- **Catalog metadata:** the pinned source entry is known.
- **Imported:** approved content was converted and committed locally with a
  matching import receipt.
- **Agent visible:** the existing per-agent skill visibility mechanism permits
  that imported directory for the selected agent.
- **Tool registered:** an existing ARTEX runtime inventory explicitly reports a
  matching dependency ID or alias.
- **Binary/hash verified:** deployment evidence verifies the actual local file
  and expected digest.
- **Runtime verified:** deployment evidence verifies the registered tool in the
  intended runtime.

A name appearing in a document establishes none of the latter five states.
The source repository supplies Markdown guidance and repository-maintenance
scripts, rather than binaries, APIs or execution adapters for the referenced
tools. This catalog performs no network request, installation, execution,
credential provisioning, permission change or new agent binding. Each separately
reviewed imported library has its own identity and requires fresh visibility
grants, as described in the
[provider visibility contract](../README.md#visibility-audit-and-readiness). Existing
ARTEX scope, approval, cancellation, isolation and usage-audit mechanisms remain
the authority for any later invocation.
