# AntiFox integration decision — 2026-11-12

## Scope and baseline

The requested integration targets ARTEX's existing Go/Norma runtime. Work starts
at `f10a194` on an isolated worktree; the original checkout at `5cddfce` and its
uncommitted discovery/intelligence changes are preserved. No deployment, external
target testing, engine replacement or upstream auto-update is part of this work.

## Sources checked before implementation

| Source | Version and license evidence | Mechanism and decision |
| --- | --- | --- |
| [AntiFox](https://github.com/AntiFox-AI/antifox/tree/070f798bf590667bc2a0a13c687dd87d8a4413bf) | Pinned commit; root `LICENSE` declares AGPL-3.0; no separate skill licenses found | 26 skill directories. `api-recon`, `playwright-cli`, and `scopesentry` match ARTEX byte-for-byte. Adapt the other 23 with a namespace, source hashes, original documents and license notices. |
| [ARTEX provider imports](https://github.com/knowlet/artex-ymh/tree/f10a194/skillprovider) | Current fork, root AGPL-3.0 | Reuse catalog schema and per-library visibility. The importer is deliberately Linux-only and publishes a replacement skill root, so it is unsuitable for merging bundled skills on macOS. Ship reviewed adapters through the existing `skills/` packaging instead. |
| Norma v0.4.3 `skill/skill.go` | Existing pinned dependency in `go.mod` | `LoadDir`, `Registry.Tool`, `${SKILL_DIR}` substitution and `OnInvoke` already provide skill loading and MCP unlocking. Reuse them without copying/replacing the SDK. |

Public discovery also covered security-agent skill/tool registries and scope
proxies. These solve adjacent problems; adding another agent runtime or scope
layer is unnecessary because this fork already has both mechanisms.

### Relevant upstream implementation

- [agent/tools_knowledge.go](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/agent/tools_knowledge.go):
  `search_knowledge` and `list_knowledge_categories` expose a global/task PostgreSQL
  knowledge service, with semantic or keyword fallback. Keep these useful tool
  names, but implement bounded offline retrieval over the current agent's visible
  skill registry. No vector service, provider secret, database search or network is
  needed. Results are reference passages, never target evidence or a skill/MCP
  invocation.
- [engine/skill/skill.go](https://github.com/AntiFox-AI/antifox/blob/070f798bf590667bc2a0a13c687dd87d8a4413bf/engine/skill/skill.go):
  its skill registry shares the existing Norma model, so replacing the runtime
  would duplicate existing behavior and lose fork improvements.
- [skills/report-generation](https://github.com/AntiFox-AI/antifox/tree/070f798bf590667bc2a0a13c687dd87d8a4413bf/skills/report-generation):
  the original skill configures AntiFox-only templates and report routes. Preserve
  those source resources for attribution/reference, but use an ARTEX report bridge
  with `list_findings`, explicit finding/node IDs, verified traffic references and
  `update_finding_report`. Do not claim AntiFox's DOCX engine or report UI exists.

## Implementation and tradeoffs

1. Ship `antifox-*` adapters for all 23 new skills. Keep original source bytes and
   the root license with every adapter; retain upstream report resources. A pinned
   provider catalog records source identity, tool dependencies and the report
   engine's unsupported direct-import boundary. Do not duplicate the three equal
   skills, install CLI programs, or infer their availability from a mention.
2. Build a deterministic, bounded lexical index at agent assembly from the same
   registry already filtered by directory name and library identity. Add the two
   read-only tools to the existing editable tool catalog. They do not invoke the
   Skill tool, modify its usage ledger, or unlock MCP servers.
3. Seed shipped skill visibility once, retaining disabled rows and user edits.
   Task-oriented specialist skills go to the planner/worker/pentest agents; the
   report bridge goes to the reporter. Custom roots/provider libraries retain the
   existing identity rules. Revocation takes effect on a fresh run, matching Skill.

The source snapshots and generic examples are reference material. Their commands
are not executed by synchronization, loading, indexing or tests. The ARTEX bridge
explicitly uses live tool schemas, existing scope/approval controls and observed
evidence rather than treating source examples as completed tests.

## Validation plan

- Deterministic bundle check, catalog/source/resource hashes, actual Norma loading
  and invocation of each adapter, reference substitution and inert frontmatter.
- English/Chinese lookup, relevance, empty/malformed/oversized input, output bounds,
  cancellation, deterministic ordering, and no implicit invocation/unlocking.
- Real disposable PostgreSQL: default seeds, explicit disable persistence, tool
  binding, visible/hidden skills, revocation and provider library identity.
- Relevant Go tests, race checks, vet and backend build. External scanners, LLMs,
  deployed services and DOCX rendering require separate runtime acceptance.

See `providers/antifox/VALIDATION.md` for executed checks and remaining limits.

## Validation-driven correction

The first real PG assembly test found that `ToggleSkillVisibilityInLibrary(false)`
and the bulk setter deleted visibility rows, while startup seeds missing built-in
rows again. A disabled shipped skill therefore became visible after a restart.
Keep disabled rows as explicit revocations; the bulk setter disables current-scope
rows before enabling the selected list. A same-name row in another library must
remain untouched by revocation. Separate generic database regression tests cover
the existing `api-recon` default, bulk replacement and cross-library behavior.

Review of the Linux-only provider assembly test exposed another compatibility
contract: raw augmentation must contain no unbound tools, before `ToolResolve`.
The knowledge tools therefore check their existing catalog bindings before
being appended. A real-PG regression first reproduced the extra-tool leak and
then verified that a newly created custom agent still receives only `Skill`.
The Linux CI workflow also runs the existing full provider integration test.
