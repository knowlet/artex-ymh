package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/xaioauth"
	"github.com/Autumn-27/norma/llm"
)

func TestXAISubscriptionConfigNoAPIKeyFallback(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "paid-openai-fixture")
	t.Setenv("ANTHROPIC_API_KEY", "paid-anthropic-fixture")
	t.Setenv("XAI_API_KEY", "paid-xai-fixture")
	cfg := ConfigFrom(xaioauth.Provider, "", "", "paid-form-fixture", "")
	if !cfg.IsSubscription() || cfg.Provider() != xaioauth.Provider || cfg.Format != llm.FormatOpenAIResponses {
		t.Fatalf("subscription identity lost: %+v", cfg)
	}
	if cfg.APIKey != "" || cfg.HasCredentials() || cfg.BaseURL != xaioauth.APIBaseURL || cfg.Model != xaioauth.DefaultModel {
		t.Fatalf("unexpected subscription credentials or defaults: %+v", cfg)
	}
	if _, err := cfg.NewProvider(); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unconnected subscription accepted a paid key: %v", err)
	}
	t.Setenv("ARTEX_LLM_PROVIDER", xaioauth.Provider)
	t.Setenv("ARTEX_LLM_BASE_URL", "")
	t.Setenv("ARTEX_LLM_MODEL", "")
	t.Setenv("ARTEX_LLM_STREAM", "false")
	fromEnv, ok := FromEnv()
	if !ok || !fromEnv.IsSubscription() || fromEnv.APIKey != "" || fromEnv.Stream {
		t.Fatalf("explicit OAuth environment lost mode: %+v, ok=%v", fromEnv, ok)
	}
	t.Setenv("ARTEX_LLM_PROVIDER", " xai-oauth ")
	fromEnv, ok = FromEnv()
	if !ok || !fromEnv.IsSubscription() || fromEnv.APIKey != "" {
		t.Fatal("whitespace in an explicit OAuth provider selected a paid key")
	}
}

func TestXAISubscriptionRejectsCredentialRoutingOverrides(t *testing.T) {
	for _, base := range []string{
		"http://api.x.ai/v1", "https://api.x.ai.attacker.invalid/v1",
		"https://api.x.ai:443/v1", "https://api.x.ai/v1?redirect=other",
		"https://someone@api.x.ai/v1", "https://api.openai.com/v1",
	} {
		t.Run(base, func(t *testing.T) {
			cfg := ConfigFrom(xaioauth.Provider, "", base, "", "")
			if _, err := cfg.NewProvider(); err == nil || !strings.Contains(err.Error(), "requires") {
				t.Fatalf("unsafe subscription base accepted: %v", err)
			}
		})
	}
	cfg := ConfigFrom(xaioauth.Provider, "", xaioauth.APIBaseURL+"/responses", "", "")
	cfg.SessionHeaderKey = "Authorization"
	if _, err := cfg.NewProvider(); err == nil || !strings.Contains(err.Error(), "session header") {
		t.Fatalf("custom authorization overwrite accepted: %v", err)
	}
}

// Use the actual Norma adapter and OAuth store/transport, with both official
// hosts routed solely to a local TLS fixture. No public service is contacted.
func xaiFixtureProvider(t *testing.T, handler http.Handler) (llm.Provider, *xaioauth.Manager) {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "paid-fixture-must-not-be-used")
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: srv.Certificate().DNSNames[0], MinVersion: tls.VersionTLS12}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "api.x.ai:443" && addr != "auth.x.ai:443" {
			return nil, fmt.Errorf("fixture refused external destination %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "session.json")
	state, _ := json.Marshal(map[string]any{"version": 1, "access_token": "oauth-access-fixture", "refresh_token": "oauth-refresh-fixture", "expires_at": time.Now().Add(time.Hour).UTC()})
	if err := os.WriteFile(path, state, 0o600); err != nil {
		t.Fatal(err)
	}
	manager := xaioauth.NewManager(path)
	cfg := ConfigFrom(xaioauth.Provider, "", "", "", "")
	cfg.OAuth = manager
	cfg.Retry.ConnectAttempts = -1
	provider, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	return provider, manager
}

func TestXAISubscriptionNormaResponsesContract(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", streaming), func(t *testing.T) {
			var requests atomic.Int32
			provider, _ := xaiFixtureProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Host != "api.x.ai" || r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer oauth-access-fixture" {
					t.Error("request did not use the official Responses endpoint and subscription token")
					w.WriteHeader(400)
					return
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				tools, ok := body["tools"].([]any)
				if body["model"] != xaioauth.DefaultModel || body["stream"] != streaming || body["store"] != false || !ok || len(tools) != 1 {
					t.Errorf("Responses request contract: %+v", body)
				}
				if streaming {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {\"delta\":\"OK\"}\n\nevent: response.output_item.added\ndata: {\"item\":{\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"fixture\"}}\n\nevent: response.function_call_arguments.delta\ndata: {\"delta\":\"{}\"}\n\nevent: response.completed\ndata: {\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n")
				} else {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"OK"}]},{"type":"function_call","call_id":"call_1","name":"fixture","arguments":"{}"}],"usage":{"input_tokens":3,"output_tokens":2}}`)
				}
			}))
			req := llm.CompletionRequest{
				Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("ping")}}},
				Tools:    []llm.ToolSchema{{Name: "fixture", Description: "local fixture only", InputSchema: map[string]any{"type": "object"}}},
			}
			ctx, capture := llmrec.NewCapture(context.Background())
			if streaming {
				var text, tool string
				for event, err := range provider.Stream(ctx, req) {
					if err != nil {
						t.Fatal(err)
					}
					if event.Type == llm.SETextDelta {
						text += event.Text
					}
					if event.Type == llm.SEToolUseStart {
						tool = event.ToolName
					}
				}
				if text != "OK" || tool != "fixture" {
					t.Fatalf("stream text=%q tool=%q", text, tool)
				}
			} else {
				message, stop, usage, err := provider.Complete(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				if stop != "tool_use" || usage.InputTokens != 3 || len(message.Content) != 2 || message.Content[1].Name != "fixture" {
					t.Fatalf("completion: %+v stop=%s usage=%+v", message, stop, usage)
				}
			}
			if requests.Load() != 1 || capture.RawRequest() == "" || strings.Contains(capture.RawRequest()+capture.RawResponse(), "oauth-access-fixture") {
				t.Fatal("request count/capture isolation failed")
			}
		})
	}
}

func TestXAISubscriptionRefreshAndCaptureRedaction(t *testing.T) {
	var calls, refreshes atomic.Int32
	provider, manager := xaiFixtureProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "auth.x.ai" && r.URL.Path == "/oauth2/token" {
			refreshes.Add(1)
			if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "oauth-refresh-fixture" {
				t.Error("refresh form mismatch")
			}
			_, _ = io.WriteString(w, `{"access_token":"rotated-access-fixture","refresh_token":"rotated-refresh-fixture","expires_in":3600,"token_type":"Bearer"}`)
			return
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"reflected oauth-access-fixture"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer rotated-access-fixture" {
			t.Error("did not use rotated token")
		}
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"error":"reflected rotated-access-fixture"}`)
	}))
	ctx, capture := llmrec.NewCapture(context.Background())
	_, _, _, err := provider.Complete(ctx, llm.CompletionRequest{})
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "access-fixture") {
		t.Fatalf("expected safe entitlement error: %v", err)
	}
	if calls.Load() != 2 || refreshes.Load() != 1 {
		t.Fatalf("calls=%d refreshes=%d", calls.Load(), refreshes.Load())
	}
	if strings.Contains(capture.RawResponse(), "access-fixture") || !strings.Contains(capture.RawResponse(), "entitlement") {
		t.Fatalf("unsafe capture: %s", capture.RawResponse())
	}
	if err := manager.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = provider.Complete(context.Background(), llm.CompletionRequest{})
	if err == nil || calls.Load() != 2 {
		t.Fatalf("cached provider bypassed logout: calls=%d err=%v", calls.Load(), err)
	}
}

func TestXAISubscriptionDoesNotFollowRedirect(t *testing.T) {
	var calls atomic.Int32
	provider, _ := xaiFixtureProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "https://api.x.ai/v1/models")
		w.WriteHeader(307)
	}))
	_, _, _, err := provider.Complete(context.Background(), llm.CompletionRequest{})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("redirect was followed: calls=%d error=%v", calls.Load(), err)
	}
}
