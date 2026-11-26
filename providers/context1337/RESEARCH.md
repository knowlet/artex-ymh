# Context1337 exercise enrichment decision (2026-11-26)

## Scope and evidence before implementation

Continue draft PR #33 on `feat/context1337-readonly-intel`. The initial remote
head was `baf8a017bcd016dcd5f98f8f7db8a4c70ff15651`; the isolated checkout
includes the subsequent unused-import fix
`f4cabd35ff33b028eeeb632547898c0609bffa7c`. The original working directory
contains unrelated changes and is not used for this implementation.

The feature is optional CVE metadata enrichment for explicitly authorized task
runs, not target discovery, exploit retrieval, validation execution or proof of
a finding. A complete CVE ID and the fixed builtin/nuclei source are the only
remote query inputs. No target names, addresses, target credentials, descriptions,
task text or evidence leave ARTEX.

| Candidate | Evidence and fit | Decision |
| --- | --- | --- |
| Existing ARTEX Context1337 CLI client | Fixed GET routes, bounded response, timeout, no redirects/proxy, exact identifier projection. Present in PR #33; ARTEX repository license applies. | Extract and reuse the client rather than implement another HTTP path. |
| Existing ARTEX `skillknowledge` integration | `server/assembly.go:wireAgentAugment`, `agent/toolcatalog.go`, `skillknowledge/tools.go`: native tool binding, strict inputs, offline operation. | Reuse the assembly/catalog pattern, with an additional per-call authorization check; do not alter offline knowledge search. |
| Existing ARTEX `intelpack` | `intelpack/intelpack.go:Load/Search`: validated offline CISA KEV and Nuclei snapshots, distinct provenance, metadata is not target evidence. | Preserve the independent offline CLI and corpus. Do not import Context1337 into the local pack or infer a finding from a match. |
| Context1337 REST/MCP | Reviewed upstream remains [b1ca024778743c3b46c380fcd0aada406b53ca57](https://github.com/wgpsec/context1337/tree/b1ca024778743c3b46c380fcd0aada406b53ca57); no explicit redistribution license found. MCP exposes a broader knowledge/content surface. | Use the existing REST adapter only; no upstream code/corpus copying, MCP tool discovery or full-content retrieval. |
| Pocman typed CVE client | [`CVEClient.Fetch` and `Metadata`](https://github.com/fressive/pocman/blob/ddb51db663147017c2457171b89cadddd0cf26e4/tui/internal/util/cve.go) use a CVE ID, request context, timeout and typed metadata; [Apache-2.0](https://github.com/fressive/pocman/blob/ddb51db663147017c2457171b89cadddd0cf26e4/LICENSE). | Design reference only. Keep ARTEX's stricter fixed origin, redirect rejection, response bound and redacted errors. No code copied or dependency added. |
| Grype optional metadata normalization | [`normalizeByCVE`](https://github.com/anchore/grype/blob/97ab4e072042100ea7795486999fadfff70ae6cb/grype/vulnerability_matcher.go) preserves the original match when optional metadata is missing or fails; [Apache-2.0](https://github.com/anchore/grype/blob/97ab4e072042100ea7795486999fadfff70ae6cb/LICENSE). | Reference the failure-isolation principle only. Do not adopt match mutation/normalization: Context1337 metadata cannot establish an ARTEX finding. No code copied or dependency added. |

## Upstream code observations

- [`internal/api/resources.go`](https://github.com/wgpsec/context1337/blob/b1ca024778743c3b46c380fcd0aada406b53ca57/internal/api/resources.go): list search accepts `q`, `type`, `source`, `enabled`, `limit`, `offset`; search results include untrusted descriptions/tags. Locally enforce exact CVE name, `vuln`, enabled and selected source, and expose only locally constructed identifiers/counts. Ignore descriptions and unknown fields. Do not follow references or fetch resource bodies.
- [`internal/auth/store.go`](https://github.com/wgpsec/context1337/blob/b1ca024778743c3b46c380fcd0aada406b53ca57/internal/auth/store.go): managed key `access:["read"]`, `sources:["builtin"]` is the smallest supported public-corpus grant and expands to nuclei; a nuclei-only source grant is rejected. Bootstrap keys have wider privileges. The client cannot attest effective key privileges from the health response.

These are source observations, not live service compatibility tests.

The analogous Go clients were searched for exact CVE metadata lookup and
optional-enrichment failure handling. Pocman's `Fetch(ctx, id)` uses a default
CVE.org origin, `GET /cve/{PathEscape(id)}`, `NewRequestWithContext` and a
ten-second client timeout; `Metadata` projects a typed `CVEMetadata`. Its
endpoint/client overrides, default redirect handling, unbounded successful JSON
and remote-body error text do not meet this integration's trust boundary.
Grype's `normalizeByCVE` returns the original match on an enrichment error or
nil metadata, illustrating optional-provider isolation; its finding-oriented
normalization is outside scope. These pinned source inspections support
extending ARTEX's existing bounded adapter rather than adding a scanner,
another HTTP client dependency or automatic metadata-to-finding conversion.

## Implementation decision

Extend existing native tool assembly with `lookup_cve_metadata`, cataloged but
unbound by default. Only planner/worker runs can receive it. Require an explicit
operator enable flag, exact task-ID allowlist, fixed origin, secret file and
native enabled per-agent binding. The handler must recheck task/exploration
identity, live task state and native binding before every request, because
agent permission bypass and ToolResolve's existing failure-open behavior cannot
be used as authorization for this integration. Never register it in the global
domain registry.

Bound requests per task per process, parallel requests, input, response size,
first-page count and time. A provider failure produces a metadata-unavailable
result and does not stop the task; task cancellation propagates. Never write
findings, graph facts, scope, instructions, tool calls or task status. Explicit
operator configuration and approved exercise execution remain separate steps.

Exercise credentials come only from an operator secret file, not an environment
secret value inherited by child processes. Same-UID tools/filesystem access are
an existing trust boundary: a secret file is not isolation from arbitrary code
running with ARTEX's filesystem permissions. Document this limitation and use a
read-only scoped key. Endpoint/task configuration is captured at startup.

## Verification plan

Mock HTTP tests cover projection, exact filter enforcement, invalid inputs,
redaction, redirect rejection, deadlines, cancellation and limits. Real native
tool assembly and disposable PostgreSQL tests cover default-off, task allowlist,
role/binding/state revocation, custom-name collisions and cross-task denial.
Run relevant package tests, race checks, vet and backend build. CI must be tied
to the final pushed head; local mocks do not establish live Context1337 or live
LLM exercise acceptance. No merge or deployment is authorized.
