# Offline skill providers

`artex provider` manages reviewed source metadata and selective instruction
imports before ARTEX initializes its server. It has no network client,
subprocess runner, tool installer, MCP configuration or database writer.

```sh
./artex provider catalog -catalog providers/claude-red/catalog.json
./artex provider status -catalog providers/claude-red/catalog.json
```

The bundled Claude-Red snapshot is a **metadata-only catalog**. Its 79 entries
remain `provenance-unverified` and cannot be imported. See
[the source evidence and dependency index](claude-red/README.md) and
[implementation research](claude-red/RESEARCH.md). Root MIT metadata does not
verify inherited document licensing. No original upstream instructions are
shipped in a loadable directory.

## Reviewed local imports

For a separately reviewed, provenance-verified schema-1 catalog, select explicit
IDs from a local pinned snapshot. This example describes harmless content:

```sh
./artex provider import -catalog reviewed-catalog.json \
  -source /absolute/path/to/reviewed-snapshot \
  -dest /absolute/path/to/new-library -select stationery,glossary
./artex provider status -catalog reviewed-catalog.json \
  -library /absolute/path/to/new-library
```

There is no automatic download, wildcard selection, provenance override or
in-place update. The source catalog is a trusted operator input, not an approval
service. Changing its provenance fields requires a separate source/content
review; a hash certifies identity rather than licensing, policy or safety.

Provider filesystem commands currently require Linux support for `O_NOFOLLOW` and
`renameat2(RENAME_NOREPLACE)`; unsupported platforms/filesystems fail closed.
The destination parent must already exist and have no symlink components. The
complete destination must be new, including when another importer or a user
creates an empty directory concurrently. Validation finishes before publication;
failed or canceled imports remove staging files through pinned private directory descriptors. One no-replace rename commits
the library atomically. Cancellation after that commit reports success. This
provides atomic visibility, not a guarantee of persistence across power loss.
Existing libraries and user edits are never merged or overwritten. Processes
with the same service UID (or root access) can already modify that UID's files;
the importer does not establish an isolation boundary against them.

Each selected skill is published as `<namespace>-<id>/SKILL.md`, matching both
its Norma display name and ARTEX visibility/audit key. Normal frontmatter uses
the original description and document license (falling back to the pinned root
license); legacy content uses the reviewed catalog description and root license.
The body, complete original source and root license are retained byte-for-byte.
Only name, description and license become active frontmatter. Original MCP,
permission and hook fields remain inert in `references/source.md`.

The importer rejects invalid paths, symlinks, nonregular files, invalid UTF-8,
empty descriptions/bodies, malformed or duplicate YAML/JSON keys, duplicate
names/aliases/source paths, unknown formats/schema versions, unpinned revisions,
missing files, size mismatches and SHA-256 mismatches. Limits: 2 MiB catalog and 32 JSON nesting levels,
100 skills, 1 MiB per source/generated skill, 64 KiB root license, 32 MiB total
source bytes and 32 MiB complete selected output (including retained originals
and licenses). File modes are 0600 and directories 0700; run administration as
the ARTEX service owner so existing access requirements stay explicit.

## Visibility, audit and readiness

Choose a new library explicitly through the existing `ARTEX_SKILL_DIR` setting
and existing deployment/configuration process. This command does not change
configuration or start/restart ARTEX. A standalone library replaces the configured
skill root; this foundation does not combine it with an existing library. Grant
individual skill-directory visibility using ARTEX's existing per-agent controls.
No agent receives a default binding. Existing usage metering records the
namespaced directory for resolved calls and records unknown-name misses.

| Report field | Evidence |
| --- | --- |
| `metadata` | Validated pinned catalog record |
| `imported` | `verified` only when receipt identity, pinned original source, deterministic conversion and all three file hashes agree; missing/mismatched evidence remains distinct |
| `agent_visible` | `unknown` offline; check existing per-agent visibility in the live deployment |
| dependency `registered` | `unknown` offline; alias resolution is metadata only |
| dependency `binary_hash_verified` | `unknown`; requires separate deployment file/hash evidence |
| dependency `runtime_verified` | `unknown`; requires separate real runtime verification |

`status` has no access to runtime inventory and never infers readiness from a
name, file presence or tool mention. A local receipt is not a signature; its
catalog digest binds metadata identity. The provider does not add a runtime
verifier or execution adapter. Empty dependency lists mean no mapping was
recorded, not that there are no requirements.

Visibility changes are applied when ARTEX assembles a fresh run. Existing runs
may already retain instruction context; revocation does not erase that context.
The existing scope, approval, cancellation and isolation mechanisms continue to
control any later tool use. There is no new attack chain or permission grant.

## Validation and removal

Tests use original harmless synthetic content, the actual Norma v0.4.3 loader and
Skill call, hostile filesystem/format inputs and a disposable real PostgreSQL
visibility/usage ledger. They do not accept a mock runner as tool validation.
`ARTEX_PROVIDER_REQUIRE_PG=1` makes missing PostgreSQL a hard test failure.
The focused [CI workflow](../.github/workflows/provider-tests.yml) builds and vets
the backend; [validation evidence](claude-red/VALIDATION.md) separates what ran
locally and remotely from runtime capabilities that remain unverified.

Remove visibility bindings through existing controls before retiring a library.
Retain any user edits and receipts for audit; roll back a configured skill root
through the normal deployment process. Reverting this PR removes the provider
code/catalog without a database migration. No deployment or tool installation
is part of this change.
