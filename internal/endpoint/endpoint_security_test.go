package endpoint

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLLMCredentialDestination(t *testing.T) {
	t.Setenv("OPENAI_BASE_URL", "")
	t.Setenv("ANTHROPIC_BASE_URL", "")
	base, err := LLM("openai", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://API.OPENAI.COM:443/v1/", "https://api.openai.com/v1/chat/completions"} {
		got, err := LLM("openai", raw, "")
		if err != nil || got != base {
			t.Fatalf("equivalent destination %q: %#v %v", raw, got, err)
		}
	}
	for _, tc := range []struct{ provider, url, proxy string }{
		{"openai-responses", "", ""}, {"openai", "http://api.openai.com/v1", ""},
		{"openai", "https://api.openai.com:8443/v1", ""}, {"openai", "https://api.openai.com/other", ""},
		{"openai", "https://other.example/v1", ""}, {"openai", "", "http://127.0.0.1:8080"},
	} {
		got, err := LLM(tc.provider, tc.url, tc.proxy)
		if err != nil || got == base {
			t.Fatalf("destination change not distinguished: %#v %v", got, err)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:11434/v1", "http://10.0.0.8/v1", "http://[::1]:11434/v1"} {
		if _, err := LLM("openai", raw, "socks5://127.0.0.1:1080"); err != nil {
			t.Fatalf("local enterprise endpoint rejected: %v", err)
		}
	}
	for _, raw := range []string{"file:///tmp/key", "https://user:secret@example.com", "https://example.com/#secret", "relative"} {
		if _, err := URL(raw); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q", raw)
		}
	}
	for _, raw := range []string{"javascript:alert(1)", "data:text/html,x", "file:///etc/passwd"} {
		if _, err := AssetURL(raw); err == nil {
			t.Fatalf("non-http asset URL accepted: %q", raw)
		}
	}
	if got, err := AssetURL("https://Example.COM/path"); err != nil || !strings.Contains(got, "example.com") {
		t.Fatalf("asset URL normalize: %q err=%v", got, err)
	}
	t.Setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
	got, err := LLM("openai", "", "")
	if err != nil || got.BaseURL != "http://localhost:11434/v1" {
		t.Fatalf("provider environment default lost: %#v %v", got, err)
	}
}

func TestRedirectDoesNotDeliverAPIKeyToOtherOrigin(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/ok" {
			if r.Header.Get("X-API-Key") != "synthetic-key" {
				t.Error("same-origin redirect lost credential")
			}
			return
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := &http.Client{CheckRedirect: CheckRedirect}
	for _, path := range []string{"/cross", "/same"} {
		req, _ := http.NewRequest(http.MethodGet, source.URL+path, nil)
		req.Header.Set("X-API-Key", "synthetic-key")
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if (path == "/cross") != (err != nil) {
			t.Fatalf("redirect %s: %v", path, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("credential redirect reached other origin")
	}
	initial, _ := http.NewRequest(http.MethodGet, "https://example.test/a", nil)
	for _, raw := range []string{"http://example.test/a", "https://example.test:444/a", "https://sub.example.test/a"} {
		r, _ := http.NewRequest(http.MethodGet, raw, strings.NewReader(""))
		if CheckRedirect(r, []*http.Request{initial}) == nil {
			t.Fatalf("cross-origin redirect accepted: %s", raw)
		}
	}
}
