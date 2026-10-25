# Cloudflare / Nginx hardening design

Reviewed on 2026-10-21, before implementation. Base: `3de6a1eeaec220d7763f167c1f89e77e411756c3` (`main`); clean checkout; no open PRs at inspection time.

## Decision and scope

Use the existing host Nginx → ARTEX deployment. Add a Cloudflare-only origin configuration, strict TLS SNI selection, sanitized forwarding headers, and loopback-only Docker publishing by default. Preserve the existing application, Gate, SSE and WebSocket handlers. Do not deploy, change DNS, or issue certificates as part of this repository change.

| Reference | Fit / license | Evidence and decision |
| --- | --- | --- |
| Nginx HTTP SSL, Real IP and Geo modules | Existing proxy architecture; upstream BSD-2-Clause-style license | Use native directives directly. No external application dependency or copied Nginx implementation. `ssl_reject_handshake` requires >= 1.19.4; this is a feature minimum, not a recommendation to deploy an unpatched old release. |
| Cloudflare proxied DNS / Full (strict) / AOP | Requested edge proxy; service documentation, not vendored code | Require Full (strict), an origin certificate and current IPv4/IPv6 peer ranges. Document optional AOP and its account-boundary limitations. |

Nginx reference commit: [`9b958b000776c88036cd800c66e7e4ad39e6fd41`](https://github.com/nginx/nginx/tree/9b958b000776c88036cd800c66e7e4ad39e6fd41) (1.28.3, used to inspect the mechanism, not as a production version recommendation). Inspected [`ngx_http_ssl_servername`](https://github.com/nginx/nginx/blob/9b958b000776c88036cd800c66e7e4ad39e6fd41/src/http/ngx_http_request.c) and [`LICENSE`](https://github.com/nginx/nginx/blob/9b958b000776c88036cd800c66e7e4ad39e6fd41/LICENSE). Absent/unmatched SNI retains the default server configuration; its `reject_handshake` path returns a fatal `unrecognized_name` TLS alert. A matching hostname selects its own certificate configuration.

## Trust boundaries

- An explicit default TLS server rejects absent/unknown SNI without a fallback certificate. `return 444` alone would occur after TLS and is insufficient.
- Real IP rewrites `$remote_addr`; Cloudflare peer authorization must use `$realip_remote_addr`, which retains the socket peer. Never apply a Cloudflare CIDR allowlist to the rewritten visitor address.
- Only official Cloudflare ranges may supply `CF-Connecting-IP`. Forward single, sanitized `X-Real-IP` / `X-Forwarded-For` values; discard untrusted `Forwarded` and alternate client-IP headers.
- Check HTTP Host independently of TLS SNI. Do not rewrite or redirect Gate POSTs. Disable proxy caching/buffering and edge caching for this control-plane hostname.
- Binding the native application to loopback disables automatic Gate activation, so hardened deployment instructions must explicitly set `ARTEX_GATE=on`.
- Application Gate rate limiting currently keys on `r.RemoteAddr`, not forwarding headers. Behind Nginx, its 10 attempts/minute limit is shared by clients using that proxy peer. This change does not silently expand application trust or claim per-visitor application limiting.
- SNI controls origin TLS only. Cloudflare edge TLS/errors are a separate connection. Correct SNI still receives the origin certificate unless a network firewall blocks the peer before TLS.
- Cloudflare IP ranges and global AOP authenticate Cloudflare infrastructure, not a particular customer zone. Custom zone/hostname AOP provides a stronger identity boundary.

## Source mapping

- TLS rejection and protocol defaults: <https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_reject_handshake>
- Original peer / trusted visitor IP: <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
- CIDR lookup: <https://nginx.org/en/docs/http/ngx_http_geo_module.html>
- WebSocket upgrade: <https://nginx.org/en/docs/http/websocket.html>
- Strict origin validation: <https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/>
- Header semantics: <https://developers.cloudflare.com/fundamentals/reference/http-headers/>
- Origin client authentication: <https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/>
- IPv4 / IPv6 snapshots: <https://www.cloudflare.com/ips-v4/> and <https://www.cloudflare.com/ips-v6/>
- Edge timeouts: <https://developers.cloudflare.com/fundamentals/reference/connection-limits/>

The configuration is authored for this repository using documented directives; no upstream source is copied. The two CIDR includes must remain identical in membership and be reviewed against both official lists before deployment or refresh.

## Acceptance

Use a local Nginx process with temporary test certificates and a mock HTTP upstream. Verify TLS 1.2/1.3 positive cases; missing/wrong SNI fails without sending a certificate; wrong Host and untrusted peers cannot reach upstream; spoofed forwarding headers do not change authorization; simulated trusted peers restore IPv4/IPv6 visitor IPs; POST body/method, SSE streaming and WebSocket upgrade survive. Validate the real configuration with `nginx -t`. Tests are local proxy integration checks, not a claim of live Cloudflare or full ARTEX end-to-end verification.

## Implementation validation (2026-10-21)

Environment: Ubuntu 24.04, locally built Nginx 1.30.6 with HTTP SSL / Real IP, OpenSSL 3.0.13. Tests use only loopback listeners and temporary certificates; they do not require ARTEX, PostgreSQL, production keys or Cloudflare credentials.

| Command / check | Exit | Result |
| --- | --- | --- |
| `NGINX_BIN=/path/to/nginx python3 scripts/test_nginx_hardening.py` | 0 | 15 tests passed; includes `nginx -t`, real TLS 1.2/1.3, origin trust, HTTP routing/headers, uploads, SSE and WebSocket frames. |
| `python3 -m py_compile scripts/test_nginx_hardening.py` | 0 | Python syntax valid. |
| `git diff --check` | 0 | No whitespace errors. |
| Independent configuration / deployment-document review | — | Fixed the discovered 1 MiB proxy upload regression by matching the existing 512 MiB workspace request limit; documented the separate Cloudflare plan limit. No remaining blocking findings in the reviewed configuration/docs. |
| Local `docker compose config` | Not run | Docker is unavailable locally; the dedicated GitHub workflow checks resolved default host bindings. |
| Full ARTEX / live Cloudflare / optional AOP / production firewall | Not run | No application code changed and no deployment was performed. These require the operator's real environment and are covered by the deployment acceptance instructions. |

The workflow uses read-only repository permissions, a pinned checkout action, bounded runtime and cancellation of superseded runs. Remote CI evidence belongs to the PR's exact head; local proxy tests alone are not a remote CI or production acceptance claim.
