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
  required keys before Norma's `{}` fallback can run. This is **not** a full
  JSON Schema validator. Empty arguments remain compatible with zero-required-
  argument tools; malformed JSON is never replaced with `{}`.
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
