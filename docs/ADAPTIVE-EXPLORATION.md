# Adaptive exploration from actual outcomes and available capabilities

This change builds on [planner progress recovery](WEBFETCH-PLANNER-RECOVERY.md).
The progress check detects an idle round; adaptive recovery gives the model
better evidence and discovery options for choosing its next action. It does
not prescribe a tool sequence, generate an attack plan in the scheduler, or
promise that a model will find a viable new direction.

## What prevented useful replanning

The previous default planner prompt permitted lightweight investigation only
at task startup and prohibited it once worker facts existed. This confused
having some evidence with having enough evidence to make the next decision.
The worker correctly stayed within its assigned intent, but the planner could
have insufficient information to formulate a different intent.

Other gaps made that decision harder:

- A fresh heartbeat included graph structure but little about recent worker
  outcomes. Completion-trigger excerpts did not survive as equivalent feedback
  in later heartbeat inputs.
- `workerOutput` and `get_worker_output` searched the oldest 1,000 activities.
  A long-running worker's actual final result could be outside that page.
- The bounded corrective session carried a conclusion and one error, without
  the corresponding inputs or ordinary JSON batch rejection details.
- A planner could discover its own tools but lacked a read-only view of the
  worker's configured capabilities when choosing what to delegate.
- Skill-gated MCP discovery did not explain which visible skill satisfied the
  prerequisite. Deferred metadata could also outlive final tool filtering.
- The planner's `parent_ids` guidance allowed prior intent IDs, while the
  handler correctly accepted only facts and findings.

These are source-verified limitations. They do not establish which one caused
a particular historical model response or prove a production success rate.

## Model-selected questions and experiments

Information gathering can be an intent even when the vulnerability or next
technical method is still uncertain. The planner should identify an unanswered
question that would change the next decision, use existing evidence to choose
a method, and specify what observation would be informative.

`add_intent` accepts an optional `exploration` object in either a single call
or an element of its existing batch input:

```json
{
  "summary": "Compare the existing service manifest with the recorded response to identify the next useful observation",
  "exploration": {
    "question": "Which documented service behavior explains the recorded response?",
    "method": "Compare the available manifest with the existing observation",
    "expected_signal": "A matching documented behavior, a specific mismatch, or missing evidence",
    "stop_condition": "Stop after one comparison or when the required record is unavailable",
    "prior_intent_ids": [42],
    "change": "Use an available record to resolve a question the earlier observation did not answer"
  }
}
```

The ID is illustrative. References must resolve to visible, terminal intents
in the current task or a directly linked source task. Active, foreign, duplicate,
invalid, and non-intent references are rejected before creating an intent.
At most four prior IDs and 600 characters per text field are accepted. When
references are present, `change` must explain the difference from the earlier
attempt. `question`, `expected_signal`, and `stop_condition` are required only
when the optional object is supplied.

This metadata is persisted with the intent and reaches the worker on each run.
The suggested method does not force a tool sequence. A worker can select a
more suitable permitted tool for the same question. It should stop at the
stated condition or its existing budget, report observed results and unresolved
questions, and return cross-direction decisions to the planner.

The plan is not evidence, a finding, a goal proof, or additional authorization.
Prior intent references do not reopen work or become evidence parents.
`parent_ids` still accepts only visible facts/findings. Existing calls without
`exploration` remain valid. The stop condition and substantive novelty are
model-facing contracts; this change does not add a semantic novelty classifier
or a programmatic evaluator for arbitrary natural-language stop conditions.

The default planner guidance now allows bounded, decision-oriented information
collection at any stage. Direct target observations still require the role's
tools and the task's constraints; the prompt limits lightweight probes to three
per round and delegates deeper work. That probe count is prompt guidance, not a
new network enforcement mechanism. The actual recovery turn/time limits are
enforced by the harness and context deadline.

## Evidence that survives the next heartbeat

Every graph overview includes a bounded `recent_worker_feedback` view for the
six newest current-task intents in `done`, `blocked`, or `exhausted` state:

- Latest final result, otherwise latest text, with its step ID and an excerpt
  of at most 800 characters.
- The latest activity ID, so a caller can distinguish an unchanged snapshot
  from additional activity.
- Tool-result/error counts from the last 128 activity rows, at most eight tool
  groups, and the latest three error excerpts of at most 240 characters each.
- Explicit sampling, truncation, and omitted-tool indicators. Counts do not
  claim to describe the entire worker history.

This view summarizes stored records mechanically. It does not synthesize facts
or decide whether an experiment succeeded. `done` means execution ended; an
error or lack of evidence does not establish that a hypothesis was disproved.
Older completed intents remain available through the existing read tools.

The completion trigger and `get_worker_output` now share the same indexed
latest-output lookup, including results beyond the original 1,000-row page.
Final results retain precedence over newer ordinary text. Direct-source
membership and terminal state are checked in the same SQL statement as an
inherited output read, with explicit source attribution. Reopened or deleted
source work is not exposed by a stale prior node lookup.

Feedback excerpts are bounded and marked as untrusted data. Existing
`get_worker_trace` read behavior remains unchanged; the supplied step IDs support
targeted full-detail reads. The new partial activity index is additive and is
created by the existing startup schema migration.

## Discovering capabilities without granting execution rights

The new `list_worker_capabilities` tool provides delegation metadata and is
initially bound to the planner through the normal tool catalog. It lists enabled
worker-bound managed tools and shell declarations, visible local skills, and
enabled MCP servers visible directly or through those skills.

Use a name/description query and follow `next_offset` when more results are
needed. Responses default to 20 entries and are capped at 50 entries and 24 KiB.
They explicitly distinguish configuration from verified runtime availability.
Session-native SDK tools are outside this metadata inventory.

Reading this inventory does not start an MCP connection, invoke tools or skills,
enable capabilities, change bindings, or grant the planner access to worker
tools. Schemas/default parameter values, execution specifications, MCP
connection details, cached tool names, and skill bodies are not returned.
Required configuration-read failures return an error without a partial fallback.

For connected, skill-gated MCP tools, existing deferred discovery now names the
visible skills that can satisfy the gate. Any one listed skill is sufficient;
reading the description alone does not unlock the tool. Final deferred/global
name lists are intersected with the actual resolved tool registry. A short
capability-discovery reminder describes only routes present in that session.

The worker still performs runtime discovery through its own tool list, `Skill`,
`SearchExtraTools`, and `ExecuteExtraTool`. The model decides which capability
answers the current question; these mechanisms are options, not mandatory steps.

## One bounded adaptive recovery phase

If an eligible idle heartbeat finishes without committed progress, it receives
one corrective phase of at most **eight model turns and 90 seconds**. A smaller
positive configured turn limit and the task's remaining deadline reduce that
budget. There is no recursive correction or additional settlement phase.

The fresh corrective input includes refreshed graph/todo state and up to eight
recent paired tool inputs/results. Excerpts are bounded, common credential
fields are redacted, and the original full input/result hashes distinguish
different IDs, queries, pages, or truncated tails. Exact repeated observations
are counted within that window. Batch `add_intent` errors are retained even
when the tool returns ordinary JSON rather than `IsError=true`.

The model can inspect a relevant new record, discover an allowed capability,
or delegate a concrete information-gathering question. It should explain how
the next action could change its decision, instead of repeatedly reading the
same completed work. A mere change of tool name is not useful progress.

Only the existing committed-intent/goal checks determine dispatch progress;
analysis, tool discovery, repeated reads, and failed calls do not satisfy them.
The existing explicitly enabled legacy `goal_met` completion signal is retained.
Provider failures, hook stops, cancellation, final settlement, refreshed active
intents, and task deadlines retain their existing behavior. The durable
three-stall warning and deduplication from the preceding change remain intact.

The initial planner session still uses its configured execution limits. If it
is configured with unlimited turns and never returns, this post-round recovery
cannot interrupt it. This change does not add a general detector for alternating
read loops in that initial session.

## Existing installations and validation

Existing stored prompts, custom descriptions, defaults, enabled states, and
bindings remain authoritative. A narrow code-owned guidance appendix explains
the new planning semantics while explicitly preserving user constraints; it
does not erase a custom prohibition on direct probing. Existing `add_intent`
schemas receive only the missing optional property at runtime. The new
inventory tool uses first-insert seeding, so later configuration edits survive
restart.

The pre-existing `ToolResolve` database-error fallback is unchanged. The new
inventory fails closed on its own metadata reads; it does not repair that
separate assembly behavior.

Regression fixtures cover the real planner/deferred-tool/intent-write path,
including discovering a capability after a rejected batch and committing a
different information-gathering intent. An unchanged-read variant exhausts the
recovery budget and still records a stall. Other tests cover task deadlines,
custom prompt preservation, output after 1,100 activity rows, source boundaries,
bounded feedback, optional-plan validation, and inventory bindings/gates.

With a disposable PostgreSQL database in `ARTEX_PG_DSN`:

```sh
ARTEX_ADAPTIVE_REQUIRE_PG=1 go test -race -count=1 -p=1 ./db ./agent ./server \
  -run '^(TestPlannerAdaptive|TestIntentExploration|TestWorkerFeedback|TestWorkerOutput|TestRecentWorkerFeedback|TestCapabilityGuidance|TestWorkerCapabilityInventory|TestSkillGatedDiscovery)'
```

The `Adaptive exploration` workflow provisions PostgreSQL and verifies that
every named regression actually ran and passed; a skipped or missing required
test fails the gate. Tests use fake providers and local records. They do not
access production targets or establish that a particular deployed model will
choose a useful route.
