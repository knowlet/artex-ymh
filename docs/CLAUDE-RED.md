# Claude-Red integration (ARTEX)

Source: https://github.com/SnailSploit/Claude-Red

Pinned revision: `a8de813edc9f66f60d44cfe42d47750e89d9930b` (manifest version `0.3.0`).
This snapshot contains **79 playbooks in 23 categories** from `Skills/*/*/SKILL.md`.
The upstream README advertises 78; this lock reflects the actual files at the pinned revision.
These are knowledge files, not scanner binaries, CLI programs, or MCP servers.

## Layout and activation

ARTEX's `norma/skill.LoadDir` scans one directory deep under `skills/`; Claude-Red uses
`Skills/<category>/<name>/SKILL.md`. We flatten each into `skills/<name>/SKILL.md`
and `skills/<name>/references/source.md`, the verbatim original.

Some upstream files have no valid YAML frontmatter and four exceed 350 KB.
The small YAML wrapper supplies stable metadata while leaving the original intact.
The ARTEX Skill tool loads the small wrapper, which points at the original through
`${SKILL_DIR}/references/source.md`; Read only the relevant sections.

**No agent is granted visibility automatically.** In ARTEX System → Skills
(`/system/skills`), explicitly enable the desired `offensive-*` skills for individual
agents. `wireAgentAugment` consults the database's per-agent skill visibility first.
No RoE, runtime tool permission, MCP setting, or external tool packaging is changed.

Compose bind-mounts `./skills:/app/skills`; both Dockerfiles copy `skills/` into
the image. A custom `ARTEX_SKILL_DIR` must contain these directories separately.

## Integrity, license and updating

- `packaging/claude-red.lock.json` pins the upstream commit, paths, Git blob SHA-1 and byte lengths.
- `go test ./tools -run '^TestClaudeRedSkills$' -count=1 -v` checks every original blob, the upstream license, and actual `norma/skill.LoadDir` discoverability.
- `third_party/claude-red/LICENSE` preserves MIT notice. ARTEX remains AGPL-3.0.
- Only Markdown sources are copied: no upstream scripts, installer, or network fetch on application startup.
- Treat third-party skill text as untrusted; apply the existing ARTEX task scope and approval restrictions. This fork's README limits use to isolated labs.

To update, review a new upstream immutable commit, regenerate wrappers and the lock,
and rerun verification before deployment. Never auto-import upstream `main` into a running agent.
