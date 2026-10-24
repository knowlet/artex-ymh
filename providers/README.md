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
The destination parent must already exist. Explicit input path components must
have no symlinks. Relative paths start from the current directory descriptor, so
a symlink-form `PWD` does not make otherwise safe relative inputs fail. The
complete destination must be new, including when another importer or a user
creates an empty directory concurrently. Validation finishes before publication;
cooperative failures or cancellations attempt cleanup through pinned private
directory descriptors. One no-replace rename commits the library atomically. Cancellation after that commit reports success. This
provides atomic visibility, not a guarantee of persistence across power loss.
Existing libraries and user edits are never merged or overwritten. Processes
with the same service UID (or root access) can already modify that UID's files;
the importer does not establish an isolation boundary against them.

Each selected skill is published as `<namespace>-<id>/SKILL.md`, matching its
Norma display name and audit label. Every import creates a new random library
identity, recorded in the receipt and `.provider-library-id`; visibility grants
combine this identity with the skill directory name. Copying an intact library
retains that logical identity, while importing the same content again creates a
new identity. Source conversion and content hashes remain deterministic. Normal frontmatter uses
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

## Interruption and command outcomes

SIGINT and SIGTERM cancel an ongoing import through its context, allowing it to
unwind and attempt staging cleanup. Cancellation before publication returns a
nonzero exit code; it does not publish the destination. A signal arriving after
the atomic rename cannot roll back a committed library. SIGPIPE is observed
separately so a closed stdout becomes an output error instead of terminating the
process before it can report that the import already committed.

| Exit code | Meaning |
| --- | --- |
| 0 | Requested action and report completed; successful import JSON includes `committed: true` |
| 1 | Import failed/canceled before commit, or a catalog/status action or its output failed |
| 2 | Invalid command or options |
| 3 | Import **committed**, but the success report could not be written; stderr names the library and says `committed=true` |

Exit 3 is still an output failure, not a successful report. Inspect the existing
library with `provider status`; do not blindly retry or delete it. Retrying the
same destination is refused and never overwrites the committed data. If both
output streams fail, exit 3 still distinguishes that committed state.

SIGKILL, a crash or host shutdown cannot run deferred cleanup and can leave a
partial or complete `.provider-stage-*` tree. Recover one exact interrupted stage
explicitly, without loading a catalog or contacting the database:

```sh
./artex provider recover -stage /absolute/path/to/.provider-stage-0123456789abcdef0123456789abcdef
```

The importer holds an exclusive directory lock and syncs an inode-bound inventory
before writing the library. Recovery pins that exact directory, refuses an active
lock, verifies private ownership/modes and every remaining file's recorded size
and hash, then removes only recognized content. Missing expected files are allowed;
unknown additions, edited or partially written files, symlinks, hardlinks, copied
inventories and malformed records are preserved for manual review. Recovery never
removes the published destination. A successful cleanup reports `recovered: true`;
exit 3 means cleanup completed but its report failed, so inspect before retrying.

There is no automatic prefix/age-based sweep. A crash before the inventory is
complete, an I/O failure, or modified contents can still require manual recovery.
Account for active imports and retain operator content before retiring unrecognized
residue. The inventory and advisory lock protect cooperating operations; they are
not an isolation boundary against another process with the same UID or root.

## Visibility, audit and readiness

Choose a new library explicitly through the existing `ARTEX_SKILL_DIR` setting
and existing deployment/configuration process. This command does not change
configuration or start/restart ARTEX. A standalone library replaces the configured
skill root; this foundation does not combine it with an existing library. Grant
individual skill-directory visibility using ARTEX's existing per-agent controls.
Import creates no visibility binding. Provider libraries require a fresh explicit
grant scoped to their random library identity; old grants for the same directory
name cannot authorize a newly imported library. Both per-agent and per-skill
visibility controls read and write the current library scope. Revocation applies
to that scope; explicitly granting the same name in a different library replaces
the former binding for that agent/name.

The additive `agent_skill_visibility.library_id` database column defaults to the
empty legacy scope, preserving grants for ordinary skill directories without
provider identity records. Provider receipts from before library identities were
introduced must be reimported into a new library and explicitly granted again.
A missing or malformed receipt/identity marker on an identified provider library
fails closed. Removing both identity records is an out-of-band conversion to a
legacy directory, outside this accidental-loss protection. Preserve both records
with the library; they are identity metadata, not signatures or a boundary against
an operator who can rewrite files. Offline status cannot inspect runtime grants
and keeps `agent_visible` unknown.

Existing usage metering records the namespaced directory for resolved calls and records unknown-name misses.

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
through the normal deployment process. A code rollback leaves the additive library identity column and its scoped
bindings in place; back up the database and remove/review provider grants before
running an older version that does not enforce library scope. No deployment or tool installation
is part of this change.
