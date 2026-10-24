package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSecurityCustomEffectiveInputs(t *testing.T) {
	secret := "synthetic-custom-tool-secret"
	g := guard.New()
	e := guard.NewEgressGuard()
	e.AddFingerprint("test", secret)
	g.SetEgress(e)
	s := &Server{m: &Manager{tasks: map[string]*Task{"42": {Guard: g}}}}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42})
	raw, _ := json.Marshal(commandExec{Command: "printf %s '" + secret + "'"})
	res, err := s.runCommandTool(ctx, raw, nil, &actool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil || !res.IsError {
		t.Errorf("rendered command must be blocked: error=%v result=%+v", err, res)
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	raw, _ = json.Marshal(httpExec{URL: srv.URL, Headers: map[string]string{"X-Test": "{value}"}})
	res, err = s.runHTTPTool(ctx, raw, map[string]any{"value": secret}, nil)
	if err != nil || !res.IsError || calls.Load() != 0 {
		t.Errorf("rendered header must be blocked before request: err=%v is_error=%v requests=%d", err, res.IsError, calls.Load())
	}
	raw, _ = json.Marshal(httpExec{URL: srv.URL})
	res, err = s.runHTTPTool(ctx, raw, nil, nil)
	if err != nil || res.IsError || calls.Load() != 1 {
		t.Errorf("ordinary local HTTP must still work: %v %+v", err, res)
	}
}

func TestSecurityCustomRedirectAndScope(t *testing.T) {
	g := guard.New()
	g.SetRoE(guard.RoEConfig{Mode: func() string { return "strict" }, Scope: func(int64) []guard.ScopeRule { return []guard.ScopeRule{{Kind: "domain", Value: "target.example"}} }, TaskIDOf: func(context.Context) int64 { return 42 }})
	s := &Server{m: &Manager{tasks: map[string]*Task{"42": {Guard: g}}}}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://outside.example/", http.StatusFound)
	}))
	defer srv.Close()
	// Even a regression must not dial the external-looking fixture destination.
	originalTransport := http.DefaultTransport
	http.DefaultTransport = customSecurityTransport(func(r *http.Request) (*http.Response, error) {
		if "http://"+r.URL.Host != srv.URL {
			return nil, fmt.Errorf("external fixture destination must never be contacted")
		}
		return originalTransport.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	raw, _ := json.Marshal(httpExec{URL: srv.URL})
	result, err := s.runHTTPTool(ctx, raw, nil, nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "RoE") {
		t.Fatalf("redirect must be gated before external request: %v %+v", err, result)
	}
	raw, _ = json.Marshal(commandExec{Command: "nmap 192.0.2.0/24"})
	result, err = s.runCommandTool(ctx, raw, nil, nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "RoE") {
		t.Fatalf("effective custom command must require scope approval: %v %+v", err, result)
	}
	raw, _ = json.Marshal(scriptExec{Code: "print('never executed')"})
	result, err = s.runScriptTool(ctx, "fixture", raw, nil, nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "RoE") {
		t.Fatalf("opaque custom script must require scope approval: %v %+v", err, result)
	}
}

type customSecurityTransport func(*http.Request) (*http.Response, error)

func (f customSecurityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
