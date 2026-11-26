# Context1337 read-only CVE metadata enrichment

ARTEX supports an operator CLI and an optional planner/worker tool for exact CVE references from an independently operated [Context1337](https://github.com/wgpsec/context1337) service. The REST and managed-key contracts were reviewed against upstream revision [b1ca024778743c3b46c380fcd0aada406b53ca57](https://github.com/wgpsec/context1337/tree/b1ca024778743c3b46c380fcd0aada406b53ca57).

No upstream code or knowledge files are bundled: an explicit redistribution license was not present in the reviewed repository. Operate and update the service separately with applicable rights to the service and its corpora. See the [implementation decision and source evidence](RESEARCH.md).

## Operator-owned service and credentials

Use a dedicated managed API key with `access: ["read"]` and `sources: ["builtin"]`. In the reviewed upstream implementation, this is the smallest supported public-corpus grant and includes `nuclei`; a nuclei-only grant is not supported. Do not use a bootstrap/admin or write key. ARTEX cannot attest the key's actual effective privileges from its health or search responses.

Set `ARTEX_CONTEXT1337_URL` to the HTTPS origin of your trusted service. Plain HTTP is accepted only for a literal loopback IP, such as `http://127.0.0.1:1337`, not a remote or Docker service hostname. Use trusted TLS for separate hosts or containers. Origins cannot contain credentials, a path prefix, query, or fragment. Agents cannot select the endpoint, credential, request route, or proxy.

## Enable automated exercise enrichment

All three authorization layers are required:

1. Before starting ARTEX, set the operator configuration below. It is captured during server tool assembly; changing these settings requires a restart.
2. List the exact IDs of the authorized tasks in `ARTEX_CONTEXT1337_TASK_IDS` (comma-separated, at most 32 distinct positive decimal IDs, without spaces or leading zeros).
3. In the existing Tools administration UI, explicitly enable and bind the native `lookup_cve_metadata` tool to `planner`, `worker`, or both. The catalog entry has no default agent bindings. Existing permission bypass modes do not authorize this tool.

| Setting | Required value for exercise use |
| --- | --- |
| `ARTEX_CONTEXT1337_EXERCISES` | `true`; unset keeps exercise enrichment disabled |
| `ARTEX_CONTEXT1337_TASK_IDS` | Exact authorized task IDs; no wildcard or task-selected endpoint |
| `ARTEX_CONTEXT1337_URL` | Fixed operator-owned service origin |
| `ARTEX_CONTEXT1337_API_KEY_FILE` | Path to a regular, non-symlink private key file, at most 4096 bytes |
| `ARTEX_CONTEXT1337_API_KEY` | Must be unset for exercise mode; retained only for the operator CLI |

Provision the key file through the operator's secret manager with private permissions, such as `0600`. Keep its contents out of task goals, command-line arguments, logs and environment secret values. The file avoids passing the secret value through the process environment to child tools. It is **not isolation from same-UID code**: Bash, Read or other tools with ARTEX's filesystem permissions may still read it. Use the scoped read-only key and restrict who can execute tools or access the ARTEX runtime.

Missing or invalid exercise configuration leaves this optional integration unavailable and does not prevent ARTEX startup or offline work. Removing a task from the startup allowlist requires a restart; disabling its tool binding or pausing/stopping the task is checked on the next call. An already dispatched request can finish within its bounded deadline unless task cancellation reaches it.

## Planner/worker behavior and evidence boundary

For an allowed, running task, the native tool accepts only:

```json
{"cve":"CVE-2999-1234","source":"builtin"}
```

The CVE above is synthetic. `source` may be omitted (defaults to `builtin`) or set to `nuclei`. The input must contain one complete CVE ID; no free-text search, target address, service banner, task description, evidence, credential or other extra field is accepted. The handler checks the current task, its exploration identity, its running/not-paused/not-queued state, the startup allowlist and the native enabled role binding on every call. A stale tool object does not bypass revoked permissions; a custom tool with the same name does not become the native provider.

Only the CVE ID and fixed filters are sent to `GET /api/resources`. Returned data is projected into locally constructed identifiers, source labels, counts and truncation status. Resource descriptions, body text, tags, URLs, exploit/PoC material, payloads, dictionaries and instructions never enter model context through this tool. No reference is followed and no remote content is executed.

Results are labeled `context1337` and `target_vulnerability: "unverified"`. Existing offline CISA KEV/Nuclei provenance stays separate; this tool does not merge their records or create a graph fact, finding, scope change, intent or follow-up tool call. Metadata can support a report's references or verification planning. A finding still requires independently observed target evidence through the existing verification flow. A metadata match alone does not prove vulnerability; no match is not proof of absence because the upstream FTS search is limited to its first page.

## Bounds, failure isolation and offline operation

- Exercise requests have a three-second total deadline, including waiting for an available request slot, with at most four concurrent requests. Task cancellation propagates through the request context.
- Each allowed task has at most 16 authorized request attempts per ARTEX process, including provider failures. There are no retries or caches. Restarting ARTEX resets this process-local budget; it is not a durable quota.
- Responses are bounded to 512 KiB and at most 20 first-page candidates. Exact CVE name, vulnerability type, enabled state and selected source are checked locally.
- No task proxy, environment HTTP proxy, redirect, insecure TLS, arbitrary destination, remote write or full resource retrieval is used. Errors exclude remote bodies, endpoint URLs and secrets.
- Provider unavailability, timeout, malformed/oversized data or unexpected filters produce an unavailable/error tool result. The adapter does not stop the task or make the provider a prerequisite for other tools. Task cancellation remains cancellation.
- `artex intel`, offline CISA KEV/Nuclei snapshots and `search_knowledge` remain independent. Server startup performs no provider network request. Disabling Context1337 does not disable those offline capabilities.

## Operator CLI

The CLI remains available independently of the exercise enable flag, task allowlist and agent binding. Set `ARTEX_CONTEXT1337_URL` and supply `ARTEX_CONTEXT1337_API_KEY` through an operator secret manager for this invocation. Avoid exposing the key in shell history or arguments. The exercise service must not inherit this environment secret value.

```sh
artex context1337 status
artex context1337 search --cve CVE-2999-1234
artex context1337 search --cve CVE-2999-1234 --source nuclei
```

The CLI uses only `GET /api/health` and `GET /api/resources`, with an eight-second request timeout and the same bounded metadata projection. Status reports enabled counts visible to the configured key, not a credential privilege attestation. Missing configuration or provider failures give a nonzero exit without a result; no database or server initialization is needed.

## Verification and limitations

Relevant checks (execution results belong in the PR's exact-head verification record):

```sh
go test -race ./context1337 -count=1 -v
go test -race ./cmd/artex/context1337.go ./cmd/artex/context1337_test.go -count=1 -v
go test -race ./server -run '^TestContext1337' -count=1 -v
```

The server integration tests use mock HTTP and disposable PostgreSQL. Set `ARTEX_PG_DSN` to a disposable test database and `ARTEX_CONTEXT1337_REQUIRE_PG=1` to make missing PostgreSQL a test failure; never point this suite at an operational database. Provider CI enforces that the `TestContext1337ExercisePG` test executes and passes. Discovery CI runs the reusable client and CLI fixture tests with the race detector.

These checks establish the tested adapter, authorization and assembly behavior. They do not establish compatibility with a deployed Context1337 service, the effective permissions of a real key, or a live model's end-to-end exercise behavior. No live service/model exercise, merge or deployment is implied by fixture/PG test success.
