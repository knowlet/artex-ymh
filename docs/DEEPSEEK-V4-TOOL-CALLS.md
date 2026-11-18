# DeepSeek V4 / OpenAI-compatible tool-call boundary

## Scope and confirmed defects

Investigated ARTEX commit `d6f12b1fda0da8259937b6fee0c3d798677cf275`, which
pins `github.com/Autumn-27/norma v0.4.3`. This is about **V4, not V4.1**.
No production LLM credentials, task database, or attack tools are needed by the
regression fixtures, and no live model call is made by them.

1. `norma/llm/openai.go:552-560` reads `tool_calls[].index` only to track starts;
   `SEToolInputJSON` carries no index. `llm/accumulate.go:49-52` appends every
   fragment to the last call. Interleaved A/B arguments therefore mix.
2. The first frame with either ID or name marks a call started. A later name is
   not propagated. ID-first/name-later streams lose the function name.
3. `llm/accumulate.go:89-101` converts invalid or truncated JSON to `{}`. This
   hides the protocol failure and can dispatch a call with fabricated arguments.
4. The Chat Completions adapter treats DSML in `content` as ordinary text.
   The client lacks a diagnostic for an unparsed tool-call representation.

`agent/capture.go` records harness events; it is **not** the tool dispatcher.
The example `intent_id` value `4` is compatible with its integer schema;
DSML's `string="false"` is not a boolean argument or a schema defect.

These are client-side findings. They do **not** prove which production server,
model checkpoint, quantization, template, or token limit caused the original
DSML emission. A malformed upstream DSML block cannot be repaired reliably by
inventing delimiters or executing regular-expression matches from prose.

## Fix and design

`internal/llmwire` is an ARTEX-local compatibility boundary, avoiding a broad
SDK upgrade or vendored SDK fork. `agent.Config.NewProvider` installs it only
for the OpenAI Chat Completions provider, outside the existing raw-capture and
quota transport. Anthropic and Responses providers are unchanged.

For requests declaring function tools:

- Keep per-response tool state keyed by the original index; retain delayed and
  fragmented function names. Release complete calls contiguously only after a
  terminal model frame and successful stream termination. The existing Norma
  accumulator then cannot mix calls. Text and reasoning continue streaming.
- Validate that arguments are JSON objects and contain the declared top-level
  required keys before Norma's `{}` fallback can run. A required value of `null`
  is rejected only when the property's explicit standard `type` excludes null.
  Nullable type unions and untyped/composed/reference schemas remain supported;
  arbitrary schema evaluation stays with the tool. This is **not** a full
  JSON Schema validator. Empty arguments remain compatible with zero-required-
  argument tools; malformed JSON is never replaced with `{}`.
- Require an explicit non-null `index` on every streamed tool-call delta;
  omitted/null indices never alias call 0. Atomic tool calls need no index.
- Reject noncanonical case-insensitive structural key aliases and duplicate
  structural keys before forwarding either SSE or atomic responses. This closes
  the map-versus-struct JSON decoding differential with Norma, including escaped
  keys and Go's Unicode case folds. Tool argument strings and vendor metadata
  remain opaque data, not protocol fields.
- Reject duplicate IDs, conflicting IDs, undeclared tools, invalid indices,
  missing finish frames, truncation/content filtering during a tool turn,
  malformed SSE JSON, and in-stream error objects. A single invalid call
  prevents all calls in that model turn from being released.
- Detect `<｜DSML｜` across content deltas while retaining only a possible marker
  suffix. Return `openai tool protocol: unparsed_dsml_tool_call`; never execute
  DSML prose or report it as a successfully completed tool call. With tools
  enabled, **literal DSML in assistant content is intentionally rejected too**.
  Requests without tools, reasoning fields, and strings inside structured tool
  arguments are not subject to this content guard.
- Do not blindly unwrap `arguments` or `input`: either can be a legitimate tool
  property. A wrapper that hides a required field produces a diagnostic instead.
- Bound each SSE frame, accumulated tool data and an atomic response to 16 MiB,
  and tool indices to 0..127. The reader is pull-based, with no extra goroutine;
  cancellation and Close propagate to the HTTP body.

Original request/response bytes remain in the existing recording transport.
For a rejected response the recording contains bytes actually consumed up to
failure, not a promise that unread bytes were drained. No retry policy, prompt,
model name, parallel-tool setting, output cap or production profile is changed.
This intentionally does not auto-retry a partly delivered turn or bypass tool
permissions. Remove the normalization shim only after upgrading to an upstream
adapter that passes these fixtures, retaining equivalent boundary validation.

## Diagnose remaining upstream DSML emission

Enable recording at `/function/llm-records`, reproduce with the exact deployed
profile, and inspect **HTTP raw** rather than normalized response bodies. The
normalized recorder does not retain tool blocks and cannot establish that the
server omitted them.

Record the exact model ID, provider URL/service and version, checkpoint/template,
stream setting, effective `tools`, `thinking`, output limit and `finish_reason`.
Keep credentials and sensitive tool output out of bug reports.

- DSML already in raw `content`, with absent structured `tool_calls`: investigate
  the upstream V4 tokenizer/template/tool parser and model generation.
- Structured deltas are correct but interleaved or ID-first: covered by this fix.
- `finish_reason=length`: increase an appropriate output budget or correct the
  serving configuration; do not execute a truncated call.
- Compare streaming and non-streaming with a harmless mock tool, fixed prompt,
  fresh history and repeated trials. `stream=false` is a diagnostic/workaround,
  not a guarantee that the upstream parser is correct.

Use the V4-specific serving documentation for the deployed engine. Do not apply
V4.1 parser settings to V4 or infer a universally fixed minimum engine version
from one closed issue. Relevant primary references:

- https://huggingface.co/deepseek-ai/DeepSeek-V4-Flash/blob/60d8d70770c6776ff598c94bb586a859a38244f1/encoding/README.md
- https://github.com/vllm-project/vllm/issues/40801
- https://github.com/Autumn-27/Norma/blob/v0.4.3/llm/openai.go
- https://github.com/Autumn-27/Norma/blob/v0.4.3/llm/accumulate.go
- https://api-docs.deepseek.com/guides/tool_calls/

## Correlate a stalled planner with wire evidence

The client fixes above are already present in merged PRs
[#24](https://github.com/knowlet/artex-ymh/pull/24) and
[#25](https://github.com/knowlet/artex-ymh/pull/25). Confirm the **running binary's
revision**, not just the checkout's revision, before attributing a later incident
to the old accumulator. They do not establish what happened in an earlier
production run, or guarantee that a model will decide to call `add_intent`.

The V4 encoding reference describes model-native DSML; the hosted API guide
returns structured `message.tool_calls` through an OpenAI-compatible client.
Using that API adapter is appropriate. For a self-hosted endpoint, its serving
engine must convert the model's native format to the advertised wire format;
the profile's model name alone does not identify that engine or its parser.

For one failed planner round, correlate the `exp<N>-planner` session and time
across activity, the transcript and the LLM record:

1. Inspect the record's `status`/`error` and **HTTP raw** request and response.
   In the request, verify that `add_intent` was actually offered in `tools` and
   note the effective model, stream and output-limit settings. In the response,
   distinguish a valid structured call from DSML in `content`/`refusal`, a
   truncated turn, or a completed answer containing only analysis/read calls.
2. If `add_intent` reached activity, inspect its paired `tool_result` by
   `tool_use_id`, including `is_error`, and the resulting graph state. A tool-use
   event proves an attempt, not successful creation. The absence of tool blocks
   from the **normalized LLM-record response** proves nothing: that view omits
   them by design.
3. A wire error such as `unparsed_dsml_tool_call`, `invalid_tool_arguments` or
   `incomplete_tool_turn` identifies a protocol failure. A complete, valid
   response that never attempted a progress tool instead points to planner/model
   behavior. Both can leave the graph idle; they require separate evidence.

Recording is opt-in and does not recover exchanges made while it was off.
`llmrec/capture.go` tees bytes read from the HTTP body before normalization;
it does not drain a rejected stream's unread tail. In addition,
`db/commands.go` caps each stored raw body to **1 MiB**, appending a truncation
marker when exceeded. Neither a missing call after such a cutoff nor an absent
finish frame in a prematurely closed capture proves the provider never sent it.
To establish that a call was entirely absent, use a completed, untruncated
exchange; otherwise retain the diagnosis as unresolved and use a bounded,
harmless reproduction at the provider. Raw bodies can contain task data and
tool output, so keep them in the existing access-controlled recording view and
redact any excerpt shared in a bug report.

### Check the actual planner turn budget

In the current schema, runtime budgets belong to `agents`; `agent_prompts`
contains versioned prompt templates. `agents.max_turns` defaults to `0`
(unlimited), and `server.agentMaxTurns` also falls back to `0` when no row is
available. The planner passes that value to Norma. This source default does
**not** establish the value stored on a deployed instance. After verifying the
deployed schema, the following read-only query reports the relevant settings:

```sql
SELECT key, max_turns, wrapup_max_turns, llm_profile_id
FROM agents
WHERE key = 'planner';
```

`wrapup_max_turns = 0` uses the separate built-in planner settlement budget
(10 turns); it does not mean settlement is disabled. The previous generic
settlement prompt permitted zero new intents without distinguishing idle
heartbeats with unfinished goals. The planner progress guard and updated
default settlement instruction handle that idle condition
separately. Verify the terminal reason and effective configured budgets before
claiming a turn cap caused the original failure; increasing a cap alone cannot
fix unparsed DSML or enforce a graph state change.

## Verification

```sh
go test -race -count=1 -v ./internal/llmwire
go test -race -count=1 -v ./agent -run '^TestOpenAIWire'
go test ./internal/llmwire -run '^$' -fuzz '^FuzzStreamBoundary$' -fuzztime=10s -parallel=2
```

The agent tests exercise the actual pinned Norma provider and accumulator through
ARTEX's `Config.NewProvider`, verify raw capture, and replay reasoning plus paired
tool results across turns. Unit fixtures also cover every rune split of a DSML
prefix, concurrent responses, delayed names, interleaved arguments, invalid JSON,
EOF/truncation, legitimate `arguments` properties, live text, cancellation, size
limits and provider/no-tool passthrough. These tests are offline model fixtures,
not evidence of a production V4 success rate.

## PR review follow-up

The CI provider gate consumes `go test -json` and requires a run event and a pass
for each explicitly listed top-level integration test, plus package success.
Renaming/removing/skipping a required test, fake PASS text in output, or an empty
selection fails the gate. The checker has its own offline unit tests.

Concurrency fixtures compare decoded call identities and complete argument
strings, not numeric prefixes (`1` must never match `12`). Additional wire and
real-provider regressions cover structural aliases/duplicates, absent/null
stream indices, required nullability, and optional indices in atomic replies.

JSON Schema `required` checks presence, not non-nullness; rejecting every null
would incorrectly reject schemas such as `{"type":["integer","null"]}`. This
shim enforces only nullability stated in a direct `type`, not `$ref` resolution,
composition, enum, nested types, or a full schema validator.
