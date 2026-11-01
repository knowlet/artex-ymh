package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/xaioauth"
	"github.com/Autumn-27/norma/llm"
)

type fakeXAIAuth struct {
	mu        sync.Mutex
	starts    int
	connected bool
	waitEnded bool
	loggedOut bool
	approve   chan struct{}
	waitErr   error
}

func (a *fakeXAIAuth) Start(context.Context) (*xaioauth.DeviceFlow, error) {
	a.mu.Lock()
	a.starts++
	a.mu.Unlock()
	return &xaioauth.DeviceFlow{
		DeviceCode: "device-secret-never-public", UserCode: "TEST-CODE",
		VerificationURI:         "https://accounts.x.ai/activate",
		VerificationURIComplete: "https://accounts.x.ai/activate?user_code=TEST-CODE",
		ExpiresAt:               time.Now().Add(time.Minute), IntervalSeconds: 5,
	}, nil
}

func (a *fakeXAIAuth) Wait(ctx context.Context, _ *xaioauth.DeviceFlow) error {
	defer func() { a.mu.Lock(); a.waitEnded = true; a.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.approve:
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.waitErr != nil {
			return a.waitErr
		}
		a.connected = true
		return nil
	}
}

func (a *fakeXAIAuth) Status() (xaioauth.Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return xaioauth.Status{Connected: a.connected}, nil
}

func (a *fakeXAIAuth) Logout(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.starts > 0 && !a.waitEnded {
		return errors.New("logout raced authorization worker")
	}
	a.connected, a.loggedOut = false, true
	return nil
}

func xaiTestServer(t *testing.T) (*Server, *fakeXAIAuth, http.Handler, string) {
	t.Helper()
	a := &fakeXAIAuth{approve: make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	s := &Server{ctx: ctx, jwtKey: testJWTKey, authkv: newMemKV(), xaiFlowAuth: a}
	t.Cleanup(func() {
		cancel()
		s.xaiLogin.opMu.Lock()
		defer s.xaiLogin.opMu.Unlock()
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := s.cancelXAILogin(ctx, ""); err != nil {
			t.Error(err)
		}
	})
	token, err := signJWT(testJWTKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s, a, s.Handler(), token
}

func xaiRequest(t *testing.T, h http.Handler, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func startXAITestLogin(t *testing.T, h http.Handler, token string) string {
	t.Helper()
	w := xaiRequest(t, h, token, "POST", "/api/llm/xai-oauth/login", "")
	if w.Code != 200 {
		t.Fatalf("login %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), "device-secret") || strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "refresh_token") {
		t.Fatalf("credential escaped login response: %s", w.Body.String())
	}
	if result["user_code"] != "TEST-CODE" || result["interval"] != float64(5) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing safe verification fields: %s", w.Body.String())
	}
	id, _ := result["flow_id"].(string)
	if len(id) < 32 {
		t.Fatal("missing opaque login ID")
	}
	return id
}

func TestXAIOAuthRoutesRequireARTEXAuthentication(t *testing.T) {
	_, a, h, _ := xaiTestServer(t)
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/llm/xai-oauth/status"},
		{"POST", "/api/llm/xai-oauth/login"},
		{"GET", "/api/llm/xai-oauth/login/unknown"},
		{"DELETE", "/api/llm/xai-oauth/login/unknown"},
		{"POST", "/api/llm/xai-oauth/logout"},
	} {
		w := xaiRequest(t, h, "", route.method, route.path, "")
		if w.Code != 401 {
			t.Errorf("%s %s bypassed admin auth: %d", route.method, route.path, w.Code)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.starts != 0 || a.loggedOut {
		t.Fatal("unauthenticated request changed authorization state")
	}
}

func TestXAIOAuthLoginLifecycleAndSafeStatus(t *testing.T) {
	s, a, h, token := xaiTestServer(t)
	id := startXAITestLogin(t, h, token)
	if w := xaiRequest(t, h, token, "POST", "/api/llm/xai-oauth/login", ""); w.Code != 409 {
		t.Fatalf("second pending login: %d %s", w.Code, w.Body.String())
	}
	if w := xaiRequest(t, h, token, "GET", "/api/llm/xai-oauth/login/wrong", ""); w.Code != 404 {
		t.Fatal("wrong flow ID accepted")
	}
	w := xaiRequest(t, h, token, "GET", "/api/llm/xai-oauth/login/"+id, "")
	if !strings.Contains(w.Body.String(), `"state":"pending"`) {
		t.Fatal(w.Body.String())
	}
	close(a.approve)
	s.xaiLogin.mu.Lock()
	done := s.xaiLogin.flow.done
	s.xaiLogin.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("authorization worker did not complete")
	}
	w = xaiRequest(t, h, token, "GET", "/api/llm/xai-oauth/login/"+id, "")
	if !strings.Contains(w.Body.String(), `"state":"complete"`) {
		t.Fatal(w.Body.String())
	}
	w = xaiRequest(t, h, token, "GET", "/api/llm/xai-oauth/status", "")
	if !strings.Contains(w.Body.String(), `"connected":true`) || strings.Contains(w.Body.String(), "token") {
		t.Fatal(w.Body.String())
	}
}

func TestXAIOAuthCancelAndLogoutJoinPendingAuthorization(t *testing.T) {
	for _, logout := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "logout"}[logout], func(t *testing.T) {
			s, a, h, token := xaiTestServer(t)
			id := startXAITestLogin(t, h, token)
			method, path := "DELETE", "/api/llm/xai-oauth/login/"+id
			if logout {
				method, path = "POST", "/api/llm/xai-oauth/logout"
			}
			w := xaiRequest(t, h, token, method, path, "")
			if w.Code != 200 {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			a.mu.Lock()
			if !a.waitEnded || a.connected || a.loggedOut != logout {
				t.Errorf("authorization lifecycle was not joined: %+v", a)
			}
			a.mu.Unlock()
			s.xaiLogin.mu.Lock()
			state := s.xaiLogin.flow.state
			s.xaiLogin.mu.Unlock()
			if state != "cancelled" {
				t.Errorf("state = %s", state)
			}
			if w := xaiRequest(t, h, token, "POST", "/api/llm/xai-oauth/login", ""); w.Code != 429 {
				t.Fatalf("login start rate limit: %d", w.Code)
			}
		})
	}
}

func TestXAIOAuthFailedAuthorizationIsVisible(t *testing.T) {
	s, a, h, token := xaiTestServer(t)
	a.waitErr = xaioauth.ErrDenied
	id := startXAITestLogin(t, h, token)
	close(a.approve)
	s.xaiLogin.mu.Lock()
	done := s.xaiLogin.flow.done
	s.xaiLogin.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("denial did not complete")
	}
	w := xaiRequest(t, h, token, "GET", "/api/llm/xai-oauth/login/"+id, "")
	if !strings.Contains(w.Body.String(), `"state":"error"`) {
		t.Fatal(w.Body.String())
	}
	status, _ := a.Status()
	if status.Connected {
		t.Fatal("denied authorization marked connected")
	}
}

func TestXAIOAuthPrivateDirectoryBoundary(t *testing.T) {
	parent := t.TempDir()
	t.Setenv("ARTEX_KEY_DIR", parent)
	path := oauthPrivatePath("unused")
	if path != filepath.Join(parent, "xai-oauth", "session.json") {
		t.Fatalf("path=%s", path)
	}
	if err := ensureOAuthDirectory(path); err != nil {
		t.Fatal(err)
	}
	if err := ensureOAuthDirectory(path); err != nil {
		t.Fatal("private directory should be reusable", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := ensureOAuthDirectory(path); err == nil {
			t.Fatal("world-readable credential directory accepted")
		}
	}
	symlinkParent := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(symlinkParent, "xai-oauth")); err == nil {
		if err := ensureOAuthDirectory(filepath.Join(symlinkParent, "xai-oauth", "session.json")); err == nil {
			t.Fatal("symlink credential directory accepted")
		}
	}
}

func TestXAIOAuthProfileRejectsCredentialAndEndpointConfusion(t *testing.T) {
	for _, tc := range []struct{ base, key, header string }{
		{"https://attacker.invalid/v1", "", ""},
		{"https://api.x.ai.evil.invalid/v1", "", ""},
		{"https://api.x.ai/v1?target=other", "", ""},
		{"http://api.x.ai/v1", "", ""},
		{xaioauth.APIBaseURL, "sso-cookie-or-key", ""},
		{xaioauth.APIBaseURL, "", "Authorization"},
	} {
		if err := validateXAIProfile(tc.base, tc.key, tc.header); err == nil {
			t.Errorf("unsafe profile accepted: %+v", tc)
		}
	}
	if err := validateXAIProfile(xaioauth.APIBaseURL+"/responses", "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestXAIOAuthQuotaNeverAdvancesToPaidTaskProfile(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "stream"}[streaming], func(t *testing.T) {
			quota := errors.New("HTTP status 402 Payment Required: subscription quota exhausted")
			provider := &scriptedLLMProvider{err: quota}
			selected, advanced := 0, 0
			hooks := taskLLMStreamHooks{
				current: func() (taskLLMSelection, error) {
					selected++
					return taskLLMSelection{provider: provider, profileID: 7, subscription: true}, nil
				},
				exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
					advanced++
					next := int64(8)
					return db.TaskLLMTransition{Advanced: true, NextProfileID: &next}, nil
				},
			}
			var err error
			if streaming {
				_, err = collectTaskLLMStream(streamTaskLLM(t.Context(), "1", llm.CompletionRequest{}, hooks))
			} else {
				_, _, _, err = completeTaskLLM(t.Context(), "1", llm.CompletionRequest{}, hooks)
			}
			if !errors.Is(err, quota) || advanced != 0 || selected != 1 || provider.calls != 1 {
				t.Fatalf("subscription advanced or retried: err=%v advanced=%d selected=%d calls=%d", err, advanced, selected, provider.calls)
			}
		})
	}
	s := &Server{}
	cfg := agent.ConfigFrom(xaioauth.Provider, "", "", "", "")
	if pool := s.poolChain(1, &scriptedLLMProvider{}, cfg); pool != nil {
		t.Fatal("subscription built paid fallback pool")
	}
}

func TestXAIOAuthMissingLoginDoesNotBorrowAPIKey(t *testing.T) {
	s := &Server{llmCfg: agent.ConfigFrom("openai", "fixture", "https://fixture.invalid/v1", "paid-key", "")}
	for _, handler := range []http.HandlerFunc{s.testLLM, s.setLLM, s.pgListModels} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"provider":"xai-oauth","base_url":"https://api.x.ai/v1"}`)))
		if w.Code >= 500 || strings.Contains(w.Body.String(), "paid-key") || strings.Contains(w.Body.String(), `"ok":true`) {
			t.Fatalf("missing login borrowed a key or reported success: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestXAIOAuthUnavailableProfileDoesNotUsePaidChatPG(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		if os.Getenv("ARTEX_XAI_REQUIRE_PG") == "1" {
			t.Fatal(err)
		}
		t.Skip("PostgreSQL not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		if os.Getenv("ARTEX_XAI_REQUIRE_PG") == "1" {
			t.Fatal(err)
		}
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	defer pg.Close()
	p := &db.LLMProfile{Name: "xai-no-login-" + time.Now().Format("150405.000000000"), Format: xaioauth.Provider, Model: xaioauth.DefaultModel, Streaming: true}
	id, err := pg.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteProfile(id)
	s := &Server{m: &Manager{pg: pg}, xaiOAuth: xaioauth.NewManager(filepath.Join(t.TempDir(), "missing", "session.json")), chatAgent: &agent.ChatAgent{}}
	cfg, ready := s.loadProfileConfig(id)
	if ready || !cfg.IsSubscription() {
		t.Fatalf("missing login lost subscription identity: ready=%t cfg=%+v", ready, cfg)
	}
	if s.resolveChatAgent(&db.Conversation{LLMProfileID: &id}) != nil {
		t.Fatal("missing subscription silently used global paid chat")
	}
	// An explicit Agent binding has higher precedence than the task/global
	// chain. Losing its subscription credentials must not erase that decision.
	planner, err := pg.GetAgentByKey("planner")
	if err != nil || planner == nil {
		t.Fatalf("planner fixture: %v", err)
	}
	previous := planner.LLMProfileID
	if err := pg.SetAgentLLMProfile("planner", &id); err != nil {
		t.Fatal(err)
	}
	defer pg.SetAgentLLMProfile("planner", previous)
	if _, boundCfg, bound := s.agentBindingProvider("planner"); bound || !boundCfg.IsSubscription() {
		t.Fatal("missing subscription binding lost its billing boundary")
	}
	s.llmOn, s.llmProv = true, &scriptedLLMProvider{}
	if s.taskRuntimeAvailable(&Task{}, "planner") {
		t.Fatal("bound subscription fell through to global paid provider")
	}
	stored, _ := pg.ProfileByID(id)
	resolved := s.resolutionFromProfile(stored, "task_chain")
	if resolved.Available || !strings.Contains(resolved.Reason, "Grok") {
		t.Fatalf("incorrect unavailable reason: %+v", resolved)
	}
	w := httptest.NewRecorder()
	s.pgActivateProfile(w, httptest.NewRequest("POST", "/", strings.NewReader(fmtIDBody(id))))
	if w.Code != 409 {
		t.Fatalf("unconnected subscription was activated: %d %s", w.Code, w.Body.String())
	}
}

func fmtIDBody(id int64) string {
	b, _ := json.Marshal(map[string]int64{"id": id})
	return string(b)
}

func TestXAIOAuthActiveProfileTransitionFailsClosedPG(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		if os.Getenv("ARTEX_XAI_REQUIRE_PG") == "1" {
			t.Fatal(err)
		}
		t.Skip("PostgreSQL not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		if os.Getenv("ARTEX_XAI_REQUIRE_PG") == "1" {
			t.Fatal(err)
		}
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	defer pg.Close()
	original, err := pg.ActiveProfile()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// A local synthetic credential fixture only. Invalid provider construction
	// must stop before any HTTP request; these values are never sent to xAI.
	fixture, _ := json.Marshal(map[string]any{
		"version": 1, "access_token": "fixture-access", "refresh_token": "fixture-refresh",
		"expires_at": time.Now().Add(time.Hour),
	})
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	profile := &db.LLMProfile{Name: "xai-transition-" + time.Now().Format("150405.000000000"), Format: xaioauth.Provider,
		Model: xaioauth.DefaultModel, Proxy: "unsupported://fixture.invalid", Streaming: true}
	id, err := pg.SaveProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if original != nil {
			_ = pg.SetActiveProfile(original.ID)
		} else {
			_, _ = pg.Exec(`UPDATE llm_profiles SET is_default=false WHERE id=$1`, id)
		}
		_ = pg.DeleteProfile(id)
	}()
	profile.ID = id
	if err := pg.SetActiveProfile(id); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: pg}, xaiOAuth: xaioauth.NewManager(path)}
	seedRuntime := func(cfg agent.Config) {
		s.llmCfg, s.llmOn = cfg, true
		s.llmProv, s.llmDirect, s.chatAgent = &scriptedLLMProvider{}, &scriptedLLMProvider{}, &agent.ChatAgent{}
	}
	assertStopped := func(t *testing.T) {
		t.Helper()
		if s.llmOn || s.llmProv != nil || s.llmDirect != nil || s.chatAgent != nil {
			t.Fatal("previous billing source survived rejected active config")
		}
	}
	t.Run("paid_to_invalid_subscription", func(t *testing.T) {
		seedRuntime(agent.ConfigFrom("openai", "fixture", "https://fixture.invalid/v1", "paid-key", ""))
		s.reapplyActiveProfile()
		assertStopped(t)
		if !s.llmCfg.IsSubscription() {
			t.Fatal("new subscription identity not retained")
		}
		w := httptest.NewRecorder()
		s.pgSaveProfile(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"format":"xai-oauth","proxy":"unsupported://fixture.invalid"}`)))
		if w.Code != 400 {
			t.Fatalf("invalid subscription proxy was persisted: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("subscription_to_keyless_api", func(t *testing.T) {
		profile.Format, profile.Proxy = "openai-responses", ""
		if _, err := pg.SaveProfile(profile); err != nil {
			t.Fatal(err)
		}
		seedRuntime(agent.ConfigFrom(xaioauth.Provider, "", "", "", ""))
		s.reapplyActiveProfile()
		assertStopped(t)
		if s.llmCfg.IsSubscription() {
			t.Fatal("previous subscription identity survived config switch")
		}
	})
}
