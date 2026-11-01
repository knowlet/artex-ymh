# xAI subscription OAuth reference

Research checked on 2026-11-02 (Asia/Taipei), before implementation.
This package is an original Go implementation of the published protocol. No
upstream implementation was copied or translated; the sources below informed
the design and interoperability constants. ARTEX is not endorsed by xAI.

## Sources and decision

| Source | Revision / license | Relevant mechanism | Decision |
| --- | --- | --- | --- |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent/tree/c7da41dd522dc19cc08bbfcfa69d4b078224b45d) | `c7da41dd522dc19cc08bbfcfa69d4b078224b45d`, [MIT, Nous Research](https://github.com/NousResearch/hermes-agent/blob/c7da41dd522dc19cc08bbfcfa69d4b078224b45d/LICENSE) | [auth_constants.py](https://github.com/NousResearch/hermes-agent/blob/c7da41dd522dc19cc08bbfcfa69d4b078224b45d/hermes_cli/auth_constants.py), [auth_xai.py](https://github.com/NousResearch/hermes-agent/blob/c7da41dd522dc19cc08bbfcfa69d4b078224b45d/hermes_cli/auth_xai.py): device authorization, rotating refresh tokens, origin pinning, entitlement failures | Reference protocol and token lifecycle; retain ARTEX's native provider |
| [Agno](https://github.com/agno-agi/agno/tree/0939e4735232ecb880d753c9d48ac8bed1e9fb10) | `0939e4735232ecb880d753c9d48ac8bed1e9fb10`, [Apache-2.0, Agno Inc.](https://github.com/agno-agi/agno/blob/0939e4735232ecb880d753c9d48ac8bed1e9fb10/LICENSE) | [oauth.py](https://github.com/agno-agi/agno/blob/0939e4735232ecb880d753c9d48ac8bed1e9fb10/libs/agno/agno/models/xai/oauth.py): `XAITokenManager`; [responses.py](https://github.com/agno-agi/agno/blob/0939e4735232ecb880d753c9d48ac8bed1e9fb10/libs/agno/agno/models/xai/responses.py): per-request bearer, one 401 retry | Reference RFC 8628 pacing and request credential resolution |
| [dvcrn/grok-oauth-proxy](https://github.com/dvcrn/grok-oauth-proxy/tree/041025fb786663c400471b58ffd79939752351fa) | `041025fb786663c400471b58ffd79939752351fa`; no root LICENSE found at this revision | Separate Go OAuth proxy service | Deployment alternative only; no implementation copied or used |

xAI's [official Hermes announcement](https://x.ai/news/grok-hermes) confirms
subscription access through the integration. The current
[Hermes guide](https://hermes-agent.nousresearch.com/docs/guides/xai-grok-oauth)
and [Agno guide](https://docs.agno.com/examples/models/xai/oauth-device-login)
both use `https://api.x.ai/v1` with subscription OAuth. They also warn that
successful browser authentication alone does not establish model entitlement or
available quota. API-key billing remains a separate path; there is no automatic
fallback to it here.

The public [OIDC metadata](https://auth.x.ai/.well-known/openid-configuration)
was read directly. It advertises `https://auth.x.ai/oauth2/device/code`,
`https://auth.x.ai/oauth2/token`, the RFC 8628 device grant, refresh-token grant,
and public-client authentication (`none`). Hermes and Agno use the same public
client ID `b1a00492-073a-47ea-816f-4c329264a828` and scopes
`openid profile email offline_access grok-cli:access api:access`.

## Implementation boundaries

- Authentication endpoints are fixed to `auth.x.ai`; display URLs are restricted
  to HTTPS on `accounts.x.ai` or `auth.x.ai`. No browser cookie extraction.
- Subscription bearers are sent only to POST `https://api.x.ai/v1/responses` and
  GET `https://api.x.ai/v1/models`, never to arbitrary provider URLs.
- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628#section-3.5) `slow_down`
  increases the interval by five seconds. Missing `verification_uri_complete`
  falls back to `verification_uri`.
- A persistent OS lock protects refresh-token rotation across processes.
  A generation in that lock file invalidates a pending login after logout or a
  newer login. Credential replacement is atomic; files are 0600 and the caller
  supplies a 0700 parent directory on Unix. Windows uses inherited directory
  ACLs (the service account must own a private directory); Unix mode checks do
  not establish equivalent Windows ACL privacy.
- Logout removes local credentials and invalidates pending local authorization.
  It does not claim to revoke the grant at xAI; use xAI account settings for that.
- Local tests inject a fake HTTP transport. They do not prove that a particular
  account has access, sufficient subscription quota, or a successful live model
  call. Real account authorization and inference remain a separate acceptance
  step.
