package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

type webFetchInput struct {
	URL                string `json:"url"`
	Extract            bool   `json:"extract"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Direct             bool   `json:"direct"`
}

// newWebFetch owns the network client rather than enabling Norma's built-in
// fetcher: the latter cannot check redirects and automatically retries directly
// after some proxy errors. Neither behavior is suitable for scoped TLS opt-ins.
func newWebFetch(proxyAddr, caCert string, g *guard.Guard) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "WebFetch",
		Description: "Fetch an HTTP(S) page or API response as Markdown. Set extract=true for HTML comments, scripts, endpoints, forms, links and meta tags. Static assets (JS, CSS, images, fonts and media) are not fetched. TLS certificates are verified by default. After a certificate error on an authorized test asset, insecure_skip_verify=true explicitly skips target certificate verification, but only within the current task's registered host/IP/network scope. With a configured proxy you must also set direct=true: this deliberately bypasses the recording/egress proxy, so that request will not be recorded there. Trusting a recording proxy CA alone does not fix its upstream certificate verification. Redirects are checked again; large responses are truncated.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":                  map[string]any{"type": "string", "description": "Absolute HTTP(S) page or API URL."},
				"extract":              map[string]any{"type": "boolean", "description": "Append HTML reconnaissance details. Default false."},
				"insecure_skip_verify": map[string]any{"type": "boolean", "description": "Explicitly skip certificate verification for an HTTPS test target within the current task's registered scope. Default false. Not allowed in unscoped chat."},
				"direct":               map[string]any{"type": "boolean", "description": "Explicitly bypass configured recording/egress proxy for this in-scope TLS exception; no proxy traffic capture. Requires insecure_skip_verify=true. Default false; required when that exception is requested with a configured proxy."},
			},
			"required": []any{"url"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ permission.Context) permission.Decision {
			var in webFetchInput
			_ = json.Unmarshal(input, &in)
			return permission.AskUser("fetch external URL: " + in.URL)
		},
		Run: func(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var in webFetchInput
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("Invalid WebFetch input: " + err.Error()), nil
			}
			if in.Direct && !in.InsecureSkipVerify {
				return actool.Errorf("direct=true requires an explicitly authorized insecure_skip_verify=true request"), nil
			}
			if in.InsecureSkipVerify && strings.TrimSpace(proxyAddr) != "" && !in.Direct {
				return actool.Errorf("A recording/egress proxy is configured. Its upstream TLS policy is separate. For an in-scope test target, explicitly set both insecure_skip_verify=true and direct=true to bypass that proxy and its traffic capture for this request."), nil
			}
			runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(runCtx, http.MethodGet, in.URL, nil)
			if err != nil {
				return actool.Errorf("Error fetching URL: " + err.Error()), nil
			}
			checkURL := func(r *http.Request) error {
				if r.URL == nil || (r.URL.Scheme != "http" && r.URL.Scheme != "https") || r.URL.Hostname() == "" || r.URL.User != nil {
					return fmt.Errorf("WebFetch requires an absolute HTTP(S) URL without userinfo")
				}
				if webFetchStaticAsset(r.URL) {
					return fmt.Errorf("WebFetch does not fetch static assets; fetch the owning page instead")
				}
				if in.InsecureSkipVerify {
					if r.URL.Scheme != "https" {
						return fmt.Errorf("insecure_skip_verify requires HTTPS; redirects to HTTP are not allowed")
					}
					if !in.Direct {
						proxyURL, proxyErr := http.ProxyFromEnvironment(r)
						if proxyErr != nil {
							return fmt.Errorf("invalid WebFetch environment proxy: %w", proxyErr)
						}
						if proxyURL != nil {
							return fmt.Errorf("an environment proxy applies to this URL; explicitly set direct=true with insecure_skip_verify=true to bypass that proxy and its traffic capture")
						}
					}
					return g.AuthorizeInsecureTLS(r.Context(), r.URL.Hostname())
				}
				return nil
			}
			if err := checkURL(request); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			transport, err := webFetchTransport(proxyAddr, caCert, in)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				// The harness already guards the initial tool input. Redirects are
				// additional operations and must pass the same egress/approval gate.
				// Run it before scope audit: Location itself may contain a secret.
				if g != nil {
					next := in
					next.URL = r.URL.String()
					data, _ := json.Marshal(next)
					blocked, reason, rewritten := g.Hooks().PreToolUse(r.Context(), "WebFetch", data)
					if blocked {
						return fmt.Errorf("WebFetch redirect blocked: %s", reason)
					}
					if len(rewritten) > 0 && !bytes.Equal(rewritten, data) {
						return fmt.Errorf("WebFetch redirect guard input rewrite is unsupported")
					}
				}
				return checkURL(r)
			}}
			request.Header.Set("User-Agent", "norma/0.4")
			response, err := client.Do(request)
			if err != nil {
				// http.Client adds the redirect URL to url.Error. A rejected
				// Location may contain an egress fingerprint, so expose the
				// underlying sanitized guard reason rather than echoing that URL.
				message := "Error fetching URL: " + webFetchError(err)
				var certificateError *tls.CertificateVerificationError
				if errors.As(err, &certificateError) {
					message += ". For an in-scope HTTPS test asset, use insecure_skip_verify=true; with a configured proxy also explicitly set direct=true (bypasses proxy and recording)."
				}
				return actool.Errorf(message), nil
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
			if err != nil {
				return actool.Errorf("Error reading URL response: " + err.Error()), nil
			}
			header := fmt.Sprintf("[%d %s] %s\n", response.StatusCode, http.StatusText(response.StatusCode), response.Request.URL)
			if in.InsecureSkipVerify {
				header += "[Explicit in-scope TLS exception: certificate verification skipped; direct request, not captured by recording proxy.]\n"
			}
			for _, field := range []string{"Server", "X-Powered-By"} {
				if value := response.Header.Get(field); value != "" {
					header += field + ": " + value + "\n"
				}
			}
			text := header + webFetchContent(body, response.Header.Get("Content-Type"), in.Extract)
			return actool.Text(actool.Capture(tc, limitWebFetchText(text, 50000))), nil
		},
	})
}

func webFetchError(err error) string {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return urlError.Err.Error()
	}
	return err.Error()
}

func webFetchTransport(proxyAddr, caCert string, in webFetchInput) (*http.Transport, error) {
	// A fresh transport prevents one exception from affecting another request or
	// reusing an insecure TLS connection in a later strict call. No process globals.
	tr := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, Proxy: http.ProxyFromEnvironment}
	if in.InsecureSkipVerify {
		// The caller positively checked task scope and any configured proxy needs
		// the separate direct opt-in. Redirects cannot leave authorized HTTPS scope.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit scoped opt-in
		tr.Proxy = nil
		return tr, nil
	}
	if proxyAddr = strings.TrimSpace(proxyAddr); proxyAddr != "" {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil || proxyURL.Hostname() == "" || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h") {
			return nil, fmt.Errorf("invalid configured WebFetch proxy URL")
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	if caCert != "" {
		pem, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("cannot read WebFetch proxy CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("invalid WebFetch proxy CA certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots}
	}
	return tr, nil
}

func webFetchStaticAsset(u *url.URL) bool {
	switch strings.ToLower(path.Ext(u.Path)) {
	case ".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".wasm", ".mp4", ".webm", ".mp3", ".wav", ".ogg":
		return true
	}
	return false
}
