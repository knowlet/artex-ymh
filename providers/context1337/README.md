# Context1337 external intelligence (operator-only)

ARTEX can query an independently operated [Context1337](https://github.com/wgpsec/context1337) service for resource counts and exact CVE references. The REST contract was reviewed against upstream revision [b1ca024778743c3b46c380fcd0aada406b53ca57](https://github.com/wgpsec/context1337/tree/b1ca024778743c3b46c380fcd0aada406b53ca57).

No upstream code or knowledge files are bundled: an explicit redistribution license was not present in the reviewed Context1337 repository. Confirm applicable licenses and your rights to operate the service and its underlying corpora before deployment. Deploy and update it separately.

## Configuration and usage

Use a dedicated API key granting read-only access to builtin (which includes nuclei). Do not use the bootstrap/admin or write key. The key is read from the process environment; avoid putting it in shell history, command-line flags, ARTEX task configuration, or agent environments.

Set `ARTEX_CONTEXT1337_URL` to the HTTPS origin of your trusted service. Plain HTTP is accepted only for a literal loopback IP, such as `http://127.0.0.1:1337`, not for a remote or Docker service hostname. For separate hosts or containers use TLS with a trusted certificate. Set `ARTEX_CONTEXT1337_API_KEY` using your operator secret manager.

```sh
artex context1337 status
artex context1337 search --cve CVE-2999-1234
artex context1337 search --cve CVE-2999-1234 --source nuclei
```

The CVE above is a synthetic example. No target data is required or transmitted. The status call reports enabled resource counts visible to the supplied key; it cannot attest the key's actual privileges. Search sends only a complete CVE ID and a fixed filter for enabled vulnerability metadata from the chosen source. Results include canonical resource IDs when the exact name matches, never resource descriptions, body text, dictionaries, payloads, or instructions. The upstream FTS result is a bounded first page, so absence of a match is not proof of absence. A matching ID is not evidence of a vulnerable asset.

## Isolation and failure semantics

- Explicit operator CLI only, not registered as an MCP/agent tool or in planner/worker prompts. No background jobs, auto-enablement, DB migrations, finding creation, or changes to offline `artex intel`.
- GET /api/health and GET /api/resources only. No remote writes or full resource retrieval.
- No task proxy, environment HTTP proxy, redirects, insecure TLS, or credential-bearing URLs. Requests time out after eight seconds and responses are bounded to 512 KiB. Errors do not include remote response bodies or secrets.
- Missing configuration, timeout, non-200, malformed response or unexpected source/type/visibility is a nonzero exit with no result. Existing CISA KEV and Nuclei offline data remain independent and available.
- If a separate Context1337 deployment is unavailable, ARTEX server startup and existing tasks are unaffected.

## Testing

```sh
go test -race ./cmd/artex/context1337.go ./cmd/artex/context1337_test.go -count=1
```

The mock HTTP contract tests do not contact a deployed Context1337 server. A live compatibility check with a locally authorized service is still required before operational adoption.
