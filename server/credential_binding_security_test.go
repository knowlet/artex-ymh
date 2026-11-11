package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/internal/endpoint"
)

func TestStoredLLMKeyIsBoundToProviderEndpointAndProxy(t *testing.T) {
	src := agent.ConfigFrom("openai", "fixture", "https://llm.example.test/v1", "synthetic-stored-key", "")
	for _, tc := range []struct {
		provider, url, proxy string
		allowed              bool
	}{
		{"openai", "https://LLM.EXAMPLE.TEST:443/v1/chat/completions", "", true},
		{"anthropic", src.BaseURL, "", false},
		{"openai-responses", src.BaseURL, "", false},
		{"openai", "http://llm.example.test/v1", "", false},
		{"openai", "https://llm.example.test/other", "", false},
		{"openai", "https://other.example.test/v1", "", false},
		{"openai", src.BaseURL, "http://127.0.0.1:8080", false},
	} {
		dst := agent.ConfigFrom(tc.provider, "fixture", tc.url, "", tc.proxy)
		err := reuseLLMKey(&dst, src)
		if tc.allowed {
			if err != nil || dst.APIKey != src.APIKey {
				t.Fatalf("equivalent endpoint failed: %v", err)
			}
		} else if !errors.Is(err, endpoint.ErrCredentialDestination) || dst.APIKey != "" {
			t.Fatalf("stored key reused for changed destination: %v", err)
		}
		dst.APIKey = "synthetic-explicit-key"
		if err := reuseLLMKey(&dst, src); err != nil || dst.APIKey != "synthetic-explicit-key" {
			t.Fatal("explicit replacement key rejected")
		}
	}
}

func TestLLMConnectionTestRejectsRelocatedStoredKeyBeforeDial(t *testing.T) {
	var hits atomic.Int32
	var expectedKey atomic.Value
	expectedKey.Store("synthetic-stored-key")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+expectedKey.Load().(string) {
			t.Error("wrong fixture key sent")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()
	s := &Server{llmCfg: agent.ConfigFrom("openai", "fixture", upstream.URL+"/v1", "synthetic-stored-key", "")}
	request := func(handler http.HandlerFunc, base, proxy, key string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"provider": "openai", "model": "fixture", "base_url": base, "proxy": proxy, "api_key": key, "streaming": false})
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("POST", "/api/llm/test", bytes.NewReader(raw)))
		return w
	}
	for _, handler := range []http.HandlerFunc{s.testLLM, s.setLLM} {
		for _, tc := range []struct{ base, proxy string }{{upstream.URL + "/other", ""}, {upstream.URL + "/v1", upstream.URL}} {
			if w := request(handler, tc.base, tc.proxy, ""); w.Code != 400 {
				t.Fatalf("changed destination status %d", w.Code)
			}
		}
	}
	if hits.Load() != 0 {
		t.Fatal("rejected configuration dialled upstream")
	}
	if w := request(s.testLLM, upstream.URL+"/v1/", "", ""); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"ok":true`)) {
		t.Fatalf("same endpoint test failed: %d %s", w.Code, w.Body.String())
	}
	expectedKey.Store("synthetic-explicit-key")
	if w := request(s.testLLM, upstream.URL+"/other", "", "synthetic-explicit-key"); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"ok":true`)) {
		t.Fatalf("explicit replacement rejected: %d %s", w.Code, w.Body.String())
	}
	if hits.Load() != 2 {
		t.Fatalf("got %d real local requests, want 2", hits.Load())
	}
}

func TestScopeSentryURLCannotRetainSecretAtNewDestination(t *testing.T) {
	const stored = "http://localhost:8080/mcp"
	if got, err := resolveCredentialEndpoint(stored, "http://LOCALHOST:8080/mcp", true); err != nil || got != stored {
		t.Fatalf("equivalent local MCP endpoint rejected: %v", err)
	}
	for _, changed := range []string{"http://localhost:8081/mcp", "http://localhost:8080/other", "https://localhost:8080/mcp", "http://10.0.0.5/mcp"} {
		if _, err := resolveCredentialEndpoint(stored, changed, true); !errors.Is(err, endpoint.ErrCredentialDestination) {
			t.Fatalf("stored secret moved: %v", err)
		}
		if _, err := resolveCredentialEndpoint(stored, changed, false); err != nil {
			t.Fatalf("explicit private MCP destination rejected: %v", err)
		}
	}
}
