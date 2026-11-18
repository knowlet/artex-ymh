# Scoped WebFetch TLS exceptions and planner progress recovery

## What the incident does and does not establish

An HTTPS request to a private test target can fail because its certificate is
self-signed or lacks an IP subject alternative name. The built-in WebFetch
previously had no per-call TLS exception. It is provided by Norma and injected
by the agent options; `server/customtool.go` executes **custom HTTP tools** and
is not the source of the built-in `Error fetching URL` message.

The previous built-in schema exposed `url` and `extract`, not
`use_recording_proxy`. Recording is selected by the agent's configured proxy.
Trusting the recording proxy's CA only verifies the client-to-proxy leg; the
recording proxy separately verifies the target's certificate. Enabling
recording is therefore not a remedy for the target certificate error.

The planner previously required progress only in its heartbeat prompt. A model
could repeatedly inspect completed work and finish its answer without changing
the graph. The P0 claim watchdog covers already-created intents waiting for a
worker; it cannot detect the absence of a new intent.

The incident's DSML explanation is separate. Merged PRs
[#24](https://github.com/knowlet/artex-ymh/pull/24) and
[#25](https://github.com/knowlet/artex-ymh/pull/25) already protect the
OpenAI-compatible wire boundary. Check the **deployed binary revision** and a
completed raw exchange before attributing a particular missing `add_intent`
call to that former defect. See [the DeepSeek diagnostic guide](DEEPSEEK-V4-TOOL-CALLS.md).

## Fetching an explicitly authorized test target

WebFetch keeps certificate verification enabled by default. For a target
registered in the current task's scope, the model can explicitly request:

```json
{
  "url": "https://192.0.2.10:8443/",
  "extract": true,
  "insecure_skip_verify": true
}
```

The example address is illustrative; it is not added to any task automatically.
The exception requires a task context and an explicit matching scope rule.
Unknown scope, a global chat without task context, and an out-of-scope host are
rejected even when ordinary ROE enforcement is `warn` or `off`. Localhost is not
implicitly authorized. Existing scope rules describe hosts, domains and
networks, not individual URL paths or ports.

For the TLS exception, DNS is resolved once per connection, every returned
address is checked, and the client dials a validated numeric address. A scoped
hostname cannot implicitly authorize loopback, link-local, unspecified,
multicast or other non-unicast destinations: those addresses must independently
match an explicit task IP/CIDR rule. Ordinary public and private unicast
addresses retain the existing domain-scope meaning. This is not a general
network sandbox for all tools.

When a proxy is configured, requesting the exception also requires an explicit
`"direct": true`. This makes the routing change visible: that request bypasses
both recording and the configured egress proxy. The tool reports that the
response was obtained directly without certificate verification. It never
silently falls back from a failed proxied request to a direct request.
The target must be directly reachable from the ARTEX host; a destination
available only through an egress or tunnel proxy can still be unreachable.

```json
{
  "url": "https://192.0.2.10:8443/",
  "insecure_skip_verify": true,
  "direct": true
}
```

Each redirected destination is checked again before it can receive the TLS
exception. HTTPS-to-HTTP redirects are rejected for verified requests too;
initial HTTP requests remain supported. Invalid redirect Location errors are
redacted even when the HTTP client rejects them before the guard can run.
The normal tool approval hooks still apply. This is a per-call
option; it does not change global TLS settings, trust every private address, or
alter the recording proxy's upstream certificate policy. A valid certificate
or a configured trusted CA remains the way to retain ordinary verified access.

Response bodies are limited to 2 MiB and tool output to 50,000 bytes. Input
truncation is reported even if HTML rendering produces little visible text.
Declared HTML charsets are decoded before text and RECON extraction, and
bounded RECON space is reserved so a long page does not erase requested forms,
script references or endpoints.

## Detecting a planner that makes no progress

The planner compares committed graph state before and after an idle heartbeat.
An attempted tool call, a failed tool result, or a textual promise is not
progress. A newly persisted intent counts even when its worker finishes before
the planner returns. Newly proven goals also count.

The legacy `goal_met` tool remains unbound by default. If an administrator has
explicitly enabled it, its existing task-completion signal is honored without
starting a corrective run. This signal comes from the tool handler, not from
assistant prose; ordinary `add_intent` / `prove_goal` progress still requires
committed graph changes.

When unfinished goals remain with no queued or running intent, a successful
round that makes no progress receives one bounded corrective attempt in the
same heartbeat: at most eight turns and 90 seconds, reduced by a smaller
positive configured turn limit or the task's remaining deadline. The correction
starts a fresh short session with the existing tools and approval hooks,
refreshed graph and todos, recent worker feedback, and a bounded digest of paired
tool inputs/results. It can discover permitted capabilities and gather relevant
decision evidence; it does not synthesize an intent or accept DSML prose as a tool call. Provider
errors are preserved rather than immediately replaying a failed exchange.
Cancellation and the task's final wrap-up prevent another work-producing run.

See [adaptive exploration](ADAPTIVE-EXPLORATION.md) for the evidence/discovery
options in that corrective phase, optional experiment metadata, and limits of
post-round recovery when an initial unlimited session has not returned.

If the initial progress snapshot cannot be read, the round returns a visible
database error and leaves the normal heartbeat in control. An unavailable
snapshot is not treated as an empty graph: that would disable the idle-goal
check and could misclassify existing intents as newly created progress.

Three consecutive idle rounds produce an actionable `planner_stalled` hint in the
exploration graph. A durable checkpoint retains the consecutive-failure state
across agent reloads and restarts. The active hint is deduplicated, and real
progress resolves the previous stall episode. The warning includes the
effective planner turn setting and terminal reason so an operator can inspect
tool results, model configuration, constraints and available evidence.

The checkpoint uses an additive `explorations.planner_progress` JSONB column,
created by the existing idempotent startup migration. It contains progress
identifiers and counters, not prompts, credentials or model response bodies.

This recovery is a liveness check, not a promise that the model can find a valid
next action or achieve the task's goal. When the bounded correction also fails,
the graph and activity provide evidence for intervention instead of silently
accepting the round as useful work.

## Verification boundaries

Regression tests use local TLS/HTTP fixtures, fake LLM providers and disposable
PostgreSQL. They exercise certificate failures, explicit scope authorization,
redirects, proxy routing, successful and failed graph writes, bounded recovery,
cancellation and durable hint deduplication. They do not access an external
target or establish a production DeepSeek success rate.

With `ARTEX_PG_DSN` pointing to a disposable PostgreSQL database, run:

```sh
go test -race -count=1 -p=1 ./guard ./db ./agent -run '^(TestInsecureTLS|TestWebFetch|TestPlannerProgress)'
go vet ./...
go test -count=1 -p=1 ./...
```

The dedicated `Planner progress and scoped WebFetch` workflow provides that
database and checks JSON test events for every required named regression. A missing,
renamed or skipped required test fails the gate rather than producing an empty
successful selection.

Runtime `max_turns` belongs to the `agents` table. Its source default is `0`
(unlimited); that does not establish the deployed value. The DeepSeek guide
includes the read-only query and the separate settlement-budget semantics.
