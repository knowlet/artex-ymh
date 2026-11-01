# Grok subscription OAuth: research and implementation decision

Date: 2026-11-02 (Asia/Taipei). Target base: `2181c4f776f2ea27dfb20cc9a35a7e7139b43634`.
Work started from a clean isolated checkout on `feat/grok-subscription-oauth-20261102`.
Existing PRs #8, #9 and #10 address unrelated traffic integrity and scanner updates.

## Requirement and evidence

Add a native Grok subscription login, like Hermes, to ARTEX's existing model
configuration and Responses transport. The subscription is server-wide and
admin-controlled, like the existing LLM profiles. Keep OAuth credentials out of
profile JSON, database API-key fields, prompts and the browsable data directory.

| Source | Version and license | Observation and decision |
| --- | --- | --- |
| [xAI announcement](https://x.ai/news/grok-hermes) | 2026-05-15 official announcement | Explicitly supports Grok subscriptions inside Hermes. This is evidence for that integration, not an ARTEX endorsement or universal client registration promise. |
| [Hermes](https://github.com/NousResearch/hermes-agent/tree/c7da41dd522dc19cc08bbfcfa69d4b078224b45d) | `c7da41dd522dc19cc08bbfcfa69d4b078224b45d`, MIT, Copyright 2025 Nous Research | `hermes_cli/auth_constants.py` and `auth_xai.py`: public client, device grant, rotating refresh token, official Responses endpoint. Reference the protocol and credential lifecycle, without embedding the Python agent. |
| [Agno](https://github.com/agno-agi/agno/tree/0939e4735232ecb880d753c9d48ac8bed1e9fb10) | `0939e4735232ecb880d753c9d48ac8bed1e9fb10`, Apache-2.0 | `libs/agno/agno/models/xai/oauth.py` and `responses.py`: same public client, RFC 8628 polling, per-request bearer resolution, one refresh after 401. Reference the protocol and failure boundaries. |
| [grok-oauth-proxy](https://github.com/dvcrn/grok-oauth-proxy/tree/041025fb786663c400471b58ffd79939752351fa) | `041025fb786663c400471b58ffd79939752351fa`; root LICENSE absent at inspection | Separate service and unconfirmed redistribution license. Do not copy or depend on it. |

Searches covered the same feature (Hermes/Grok subscription login) and protocol
(xAI OAuth device authorization / Responses API), official documentation and
upstream source. The public OIDC metadata at
`https://auth.x.ai/.well-known/openid-configuration` confirms the device and token
endpoints. Source observation and public metadata reads are not an authenticated
subscription acceptance test.

## Design

Use a Go `xaioauth` package and extend the existing `xai-oauth` profile selection
to the Norma Responses adapter. Do not introduce a reverse proxy, browser-cookie
extraction or a second agent runtime. Sources above are design references; no
source code is copied or translated wholesale. Their licenses are recorded for
provenance, and ARTEX remains under its existing AGPL-3.0 license.

The upstream public client ID is `b1a00492-073a-47ea-816f-4c329264a828`, with
`openid profile email offline_access grok-cli:access api:access`. Allow operators
to supply their own registered client via `ARTEX_XAI_CLIENT_ID`. Authorization
and inference go only to the verified official origins. Authorization codes and
tokens must never follow redirects or travel to a configurable model base URL.

Persist rotating tokens atomically with private file permissions, coordinate
refreshes, handle cancellation/denial/expiry, and stop invalid refresh grants.
Keep credentials in `xai-oauth/session.json` beneath the existing private key
location, outside ARTEX's browsable workspace. Status responses reveal no token.
Logout clears local credentials and pending authorizations; remote revocation
remains available in the xAI account settings.

The OAuth provider uses subscription entitlement; selecting it never borrows an
API key or automatically advances to a paid provider after quota exhaustion.
HTTP 403 is an entitlement error, not a reason to keep reauthorizing. The
[Hermes guide](https://hermes-agent.nousresearch.com/docs/guides/xai-grok-oauth)
documents observed tier restrictions despite successful browser login. Paid xAI
API access remains a separate explicit API-key configuration.

## Verification plan

Use deterministic local HTTP fixtures for device login, slow-down, expiry,
cancellation, rotating refresh, concurrent access, revoked grants, redirect
rejection, secret redaction, streaming/text/tool Responses and no paid fallback.
Exercise profile persistence with a disposable PostgreSQL instance, the actual
built CLI without service initialization, frontend type checking and static
build, and existing relevant Go regressions. Record actual counts and skipped
tests. No user's subscription login or real model inference is implied by mocks.

Before publishing, inspect all workflow triggers. The existing release workflow
is tag-only; PR paths invoke read-only test/build workflows with disposable
services. No deployment, release, paid LLM call or scanner invocation is needed
for this feature. Final commands and results belong in the PR verification
section and `docs/GROK-SUBSCRIPTION.md`.
