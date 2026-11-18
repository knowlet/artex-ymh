package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

func TestLLMTransportTimeoutConfiguration(t *testing.T) {
	for _, raw := range []string{"", "-1", "invalid", "9223372036854775807"} {
		t.Setenv("ARTEX_LLM_IDLE_TIMEOUT", raw)
		if got := llmTransportTimeout("ARTEX_LLM_IDLE_TIMEOUT"); got != 120*time.Second {
			t.Fatalf("%q: got %v", raw, got)
		}
	}
	t.Setenv("ARTEX_LLM_HEADER_TIMEOUT", "37")
	t.Setenv("ARTEX_LLM_IDLE_TIMEOUT", "0")
	c, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatal(err)
	}
	idle := c.Transport.(quotaAwareTransport).base.(idleTimeoutTransport)
	base := idle.base.(*http.Transport)
	defer base.CloseIdleConnections()
	if idle.timeout != 0 || base.ResponseHeaderTimeout != 37*time.Second || c.Timeout != 0 {
		t.Fatalf("incorrect timeout layering: idle=%v header=%v totalHTTP=%v", idle.timeout, base.ResponseHeaderTimeout, c.Timeout)
	}
}

func TestLLMTransportResponseHeaderTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ResponseHeaderTimeout = 40 * time.Millisecond
	defer base.CloseIdleConnections()
	client := &http.Client{Transport: idleTimeoutTransport{base: base, timeout: time.Second}}
	start := time.Now()
	_, err := client.Get(srv.URL)
	if err == nil || !IsTransientModelError(err) || time.Since(start) > 2*time.Second {
		t.Fatalf("header wait was not bounded and transient: %v (%v)", err, time.Since(start))
	}
}

func TestLLMTransportIdleResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	client := &http.Client{Transport: idleTimeoutTransport{base: http.DefaultTransport, timeout: 40 * time.Millisecond}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	var idle *ResponseIdleTimeoutError
	if !errors.As(err, &idle) || !IsTransientModelError(err) {
		t.Fatalf("silent response was not an idle timeout: %v", err)
	}
}

func TestLLMTransportHealthyStreamAndSlowConsumer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 12 {
			_, _ = io.WriteString(w, "a")
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()
	client := &http.Client{Transport: idleTimeoutTransport{base: http.DefaultTransport, timeout: 150 * time.Millisecond}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	// More than the idle interval spent outside Read must not cancel the HTTP
	// request, even though the response lasts longer than one idle interval.
	time.Sleep(200 * time.Millisecond)
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(first)+string(rest) != strings.Repeat("a", 12) {
		t.Fatalf("healthy stream interrupted: first=%q rest=%q err=%v", first, rest, err)
	}
}

func TestLLMTransportCallerCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	client := &http.Client{Transport: idleTimeoutTransport{base: http.DefaultTransport, timeout: time.Second}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cancel()
	_, err = io.ReadAll(resp.Body)
	var idle *ResponseIdleTimeoutError
	if !errors.Is(err, context.Canceled) || errors.As(err, &idle) || IsTransientModelError(err) {
		t.Fatalf("caller cancellation was reclassified: %v", err)
	}
}

func TestProviderStalledStreamUsesIdleTimeout(t *testing.T) {
	t.Setenv("ARTEX_LLM_IDLE_TIMEOUT", "1")
	t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "5")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	cfg := ConfigFrom("openai", "fixture", srv.URL, "fixture-key", "")
	cfg.Retry.ConnectAttempts, cfg.Retry.EmptyAttempts = -1, -1
	p, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	// Include tool schemas to exercise the complete transport stack, including
	// llmwire and Norma's SSE decoder, before the error reaches the task router.
	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("fixture")}, Tools: []llm.ToolSchema{{Name: "fixture", InputSchema: map[string]any{"type": "object"}}}}
	start := time.Now()
	for _, e := range p.Stream(context.Background(), req) {
		if e != nil {
			err = e
		}
	}
	var idle *ResponseIdleTimeoutError
	if !errors.As(err, &idle) || time.Since(start) > 3*time.Second {
		t.Fatalf("idle timeout lost through provider layers: %v (%v)", err, time.Since(start))
	}
}
