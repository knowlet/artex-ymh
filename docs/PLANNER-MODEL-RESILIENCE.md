# Planner and worker recovery from model failures

## Incident interpretation

The supplied 2026-11-18 logs show planner calls starting at 04:56:11,
05:18:43 and 05:41:11 UTC. Each returned an nginx HTML 504 after approximately
12 minutes 30 seconds; the next call began approximately ten minutes later.
That establishes the observed wait/retry cycle. It does not identify which
nginx hop timed out, whether the upstream model was still computing, or which
binary/configuration was running. Changing ARTEX cannot repair an unavailable
upstream gateway.

The 130 `规划完成` records establish successful returns, not 130 useful plans or
130 findings. Likewise, an intent in `done` has finished execution; it is not a
finding or proof of an achieved goal. Use the `findings` table and goal state
separately. The supplied truncated node sample mixes explorations, so join
through `tasks.exploration_id` before assigning nodes to task 1 or task 2.

The baseline for this change is `2d43bff860c5446fce951e7d9812398997371f22`.
It already includes:

- [#27](https://github.com/knowlet/artex-ymh/pull/27): scoped WebFetch TLS
  exceptions and committed planner progress checks.
- [#28](https://github.com/knowlet/artex-ymh/pull/28): bounded adaptive planning
  with recent worker feedback and capability discovery.
- [#29](https://github.com/knowlet/artex-ymh/pull/29): complete DSML batches
  converted into structured tool calls.

Those changes do not prove the running deployment contains them. In particular,
baseline `agent/calltimeout.go` already defaults to a 600-second logical
provider-call deadline. A roughly 750-second 504 therefore also requires
checking the deployed revision and `ARTEX_LLM_CALL_TIMEOUT`, not assuming the
current source has no timeout at all.

## Argument compatibility without changing intent semantics

`add_intent` accepts a single intent object or an `intents` array. Its original
handler unmarshalled directly into that union. A syntactically valid
`{"arguments":"..."}` envelope was ignored as an unknown property and produced
an empty summary. Valid JSON and a valid domain request are different checks.

The handler now unwraps up to four exact, single-property `arguments`
envelopes. A layer can contain an object or a JSON-encoded object string.
Normalization is specific to the unambiguous single-property `arguments`
envelope. `add_intent`, `report_finding`, and `record_fact` handlers accept the
same unwrapped shape. For OpenAI wire validation, tools with required schema
fields (including `report_finding`) now unwrap that envelope before required-key
checks and forward the unwrapped JSON to tool handlers. `add_intent` still keeps
wrapped audit bytes on the wire when its schema has no required fields.
Integer IDs are kept as their original JSON bytes and raw provider audit captures
are unchanged.

Ambiguous siblings, duplicate top-level keys at any unwrapped layer, incorrectly
cased envelope keys, malformed/non-object payloads,
more than four wrappers, and input larger than 1 MiB are rejected explicitly.
For a batch, `asset_ids`, `parent_ids`, and other intent fields must be inside
each item; they are not silently discarded or guessed to be shared defaults.

Canonical examples:

```json
{"summary":"Inspect the authorized fixture","asset_ids":[1],"parent_ids":[5]}
```

```json
{"intents":[{"summary":"Inspect the authorized fixture","asset_ids":[1],"parent_ids":[5]}]}
```

Existing asset, admission, and evidence-parent validation runs after parsing.
An intent is still not a valid fact/finding parent. The model must select a
visible evidence node or use the existing top-level/root behavior. The server
does not remap an invalid intent parent into fabricated evidence.

Exact duplicate active intents now reuse the existing ID. Admission is serialized
per exploration in PostgreSQL and commits the node, asset anchors and parent
evidence edges together. Identity requires the same complete JSON payload,
asset set, parent-evidence set and origin; priority changes do not reset work.
Open (including cooling), running and paused work retain their state and retry
budget. Different evidence, assets or exploration metadata remains independent.
Repeated planner admissions also reuse terminal work without reopening it.
Only new evidence or explicit human reruns may initiate further work; terminal
PoC follow-ups and pauses no longer emit replacement-work instructions.
Historical duplicates are not rewritten.
This is exact admission idempotency, not semantic deduplication or a general
exactly-once guarantee for tool execution.

`report_finding` also rejects missing/blank `vulnclass`, `severity` or `summary`
before persistence or notification. Malformed inputs must produce a tool error,
not a successful empty finding. This does not establish that any observed access
constitutes a vulnerability, and does not create findings from facts automatically.

## Bounds and retry classification

| Setting | Default | What it bounds |
| --- | --- | --- |
| `ARTEX_LLM_HEADER_TIMEOUT` | 120 seconds | Waiting for response headers after writing one HTTP request |
| `ARTEX_LLM_IDLE_TIMEOUT` | 120 seconds | A blocked response-body read with no incoming bytes |
| `ARTEX_LLM_CALL_TIMEOUT` | 600 seconds | One logical model call, including task-router retries and profile failover |

Values are non-negative integer seconds; `0` disables that individual bound.
Invalid/overflowing values use the default. The Docker Compose service forwards
all three settings; editing the host's `.env` without recreating the service
does not change a running container.

The body watchdog measures blocked reads, so time spent processing a received
chunk does not expire the connection. A healthy stream can exceed one idle
interval, up to the independent total call deadline. SDK retries can make the
overall failure take longer than 120 seconds. The task-router deadline now
stays the same across retries instead of restarting its allowance each time.
User cancellation and the earlier task deadline retain priority.

Planner and worker retries share a conservative transient-error classifier:
HTTP 408, genuine rate-limit 429, 5xx, EOF/reset/network failures, and model-call
timeouts can recover by waiting. Authentication/configuration errors, quota
exhaustion, malformed tool output, context overflow, and unknown errors are not
automatically replayed as transport failures.

LiteLLM's `ContextWindowExceededError` and `context_window_exceeded` aliases
are normalized so Norma's existing bounded reactive compactor recognizes them.
The original error remains wrapped. This enables compression recovery; it
does not claim that every overlong prompt can be compressed sufficiently or
that the single reported context error caused the later 504 outage.

## Planner cooldown

After a transient failure, the planner schedules another round after 30 seconds,
then one minute, two minutes, and a maximum five minutes for continued failures.
Incoming notifications cannot bypass that cooldown. A successful round or a
non-transient result restores the ordinary task heartbeat. Existing pause,
deletion, task completion, deadline, and settlement guards still apply.

This cooldown is a planner-loop timer. Worker recovery below is separately
persisted. The planner's existing no-progress correction remains bounded and
requires real committed graph progress; a 504 does not count as useful work.

## Durable worker recovery

The former worker policy retried `model_error` twice, three seconds apart,
inside the same worker execution. Once those attempts ended, the intent became
`blocked`. There was no durable future retry time, and classification included
errors that waiting cannot fix.

For eligible transient failures, recovery now stores `model_retry_count` and
`model_retry_at` on the intent. Defaults allow two additional attempts, after
one minute and five minutes. If the existing global policy allows more attempts,
later default cooldowns are 30 minutes; a positive configured interval keeps its
fixed-delay meaning. The existing capped retry count and disable setting apply.

The intent remains `open` and visible in the graph during cooldown. A separate
ready frontier and the atomic claim both enforce the due time, so cooling work
does not occupy a worker or disappear from planner/admission/completion checks.
The count survives process restart and pause/resume. A deliberate manual rerun
starts a new retry budget. Existing `blocked` intents are not automatically
reopened during migration.

Recovery continues the same per-intent transcript. Before scheduling, ARTEX
checks that observed tool executions have matching persisted results from this
attempt, and that there are no unfinished calls. Historical results with a
reused call ID cannot stand in for newly executed work. Missing, corrupted, or
incomplete history stops automatic recovery. The worker rechecks the transcript
when a scheduled attempt starts and no longer ignores a failed resume.

Norma also records copies of retained tool messages during compaction. An
attempt that executed tools and crossed a compaction boundary is conservatively
excluded from automatic recovery, because copied historical results must not
be mistaken for newly persisted side effects. A pre-tool transport failure can
still recover after compaction.

This prevents automatic recovery from silently restarting an intent after losing
its tool history. It is not an exactly-once guarantee for arbitrary external
tools or model choices. When safe recovery cannot be established, or the budget
or remaining task time is exhausted, the intent remains visibly blocked and an
activity explains why. Infrastructure failure is not evidence that the target
has no vulnerability.

The two retry columns are added by the existing idempotent startup schema
migration. No historical findings or blocked nodes are rewritten.

## Deployment verification

First identify the image and build actually running. Compare its build/revision
with the source containing these changes; container uptime alone cannot do so.
Inspect only the relevant timeout variables, not a full environment dump that
could contain credentials. Confirm that the stored planner prompt/tool binding
and task scope permit the desired action; source defaults do not override
administrator edits.

Run the read-only diagnostic query on the authorized deployment:

```sh
docker exec -i artex-ymh-postgres-1 psql -U artex -d artex -X \
  -v ON_ERROR_STOP=1 -v task_id=2 -v since_hours=24 \
  < scripts/diagnose_planner_resilience.sql
```

The script uses a read-only transaction and a statement timeout. It separates
tasks, lists intent timestamps, checks actual findings, quantifies argument
nesting, and locates model failures using `created_at, id`. It avoids `ctid` and
does not print tool request bodies, evidence, credentials, or JWT values.
It requires PostgreSQL 16+ (`pg_input_is_valid`); the standard deployment uses 17.

After deploying, verify that transient errors show a bounded wait and an explicit
next attempt, that a scheduled worker resumes its existing session, and that
new findings appear in `findings` when the model actually records one. These
checks require the deployment; fixture tests do not establish a production
finding count or identify the failed nginx hop.

For scoped self-signed HTTPS access and the proxy/direct distinction, see
[WebFetch and planner progress](WEBFETCH-PLANNER-RECOVERY.md). For choosing a new
evidence-driven direction, see [adaptive exploration](ADAPTIVE-EXPLORATION.md).

## Automated verification

`Planner and worker model resilience` runs fixture HTTP streams, actual Norma
provider/planner/worker paths, and disposable PostgreSQL tests with the race
detector. Named assertions require the selected regressions to emit PASS; an
unavailable database or skipped regression cannot silently satisfy this gate.
Existing WebFetch/progress, adaptive-exploration, and full regression workflows
continue to cover their respective behavior.
