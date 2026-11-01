package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/xaioauth"
)

// Login credentials belong to this ARTEX installation, never to a browser or
// an LLM profile row. This interface also lets lifecycle tests use an offline
// authorization server without exposing production endpoint overrides.
type xaiFlowAuth interface {
	Start(context.Context) (*xaioauth.DeviceFlow, error)
	Wait(context.Context, *xaioauth.DeviceFlow) error
	Status() (xaioauth.Status, error)
	Logout(context.Context) error
}

type xaiLogin struct {
	id      string
	state   string
	err     string
	cancel  context.CancelFunc
	done    chan struct{}
	expires time.Time
}

type xaiLoginState struct {
	// Operations serialize start/cancel/logout, but status polling never waits
	// for the network. mu protects only the small public state snapshot.
	opMu      sync.Mutex
	mu        sync.Mutex
	flow      *xaiLogin
	lastStart time.Time
}

func (s *Server) xaiAuth() xaiFlowAuth {
	if s.xaiFlowAuth != nil {
		return s.xaiFlowAuth
	}
	if s.xaiOAuth == nil {
		return nil
	}
	return s.xaiOAuth
}

func (s *Server) configureSubscription(cfg *agent.Config) {
	if cfg.IsSubscription() {
		cfg.OAuth = s.xaiOAuth
		cfg.APIKey = ""
	}
}

// oauthPrivatePath validates the credential directory itself, not just the JWT
// key directory. For example keyDir=/app with dataDir=/app/xai-oauth is safe for
// /app/jwt.key but would put the OAuth session inside the browsable workspace.
func oauthPrivatePath(keyDir, dataDir string) (string, error) {
	if configured := strings.TrimSpace(os.Getenv("ARTEX_KEY_DIR")); configured != "" {
		keyDir = configured
	}
	keyDir, err := filepath.Abs(keyDir)
	if err != nil {
		return "", err
	}
	keyDir, err = filepath.EvalSymlinks(keyDir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve Grok private key directory: %w", err)
	}
	privateDir := filepath.Join(keyDir, "xai-oauth")
	if info, err := os.Lstat(privateDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("Grok credential directory must be a real directory")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	workspace, err := resolveOAuthStoragePath(dataDir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve Grok workspace boundary: %w", err)
	}
	resolvedPrivate, err := resolveOAuthStoragePath(privateDir)
	if err != nil {
		return "", err
	}
	if rel, err := filepath.Rel(workspace, resolvedPrivate); err != nil {
		return "", err
	} else if rel == "." || filepath.IsLocal(rel) {
		return "", fmt.Errorf("Grok credential directory must be outside the browsable workspace")
	}
	return filepath.Join(privateDir, "session.json"), nil
}

// Resolve existing symlink ancestors even when the final data/private directory
// has not been created yet. Comparing only lexical paths or ignoring ENOENT from
// EvalSymlinks would miss aliases such as workspace-link/xai-oauth.
func resolveOAuthStoragePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(abs)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		// A dangling symlink is not a missing directory we can safely project.
		if info, statErr := os.Lstat(abs); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("cannot resolve dangling Grok storage path")
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", err
		}
		missing = append(missing, filepath.Base(abs))
		abs = parent
	}
}

func (s *Server) initXAIOAuth(keyDir, dataDir string) error {
	// Validate before constructing a manager, including for an existing session.
	// An unsafe path disables this provider without stopping API-key providers.
	s.xaiOAuth, s.xaiOAuthPath = nil, ""
	path, err := oauthPrivatePath(keyDir, dataDir)
	if err != nil {
		return err
	}
	s.xaiOAuthPath = path
	s.xaiOAuth = xaioauth.NewManager(path)
	return nil
}

func ensureOAuthDirectory(path string) error {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("cannot create private Grok credential directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Grok credential directory must be a real directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		return fmt.Errorf("Grok credential directory must have mode 0700")
	}
	return nil
}

func (s *Server) registerXAIOAuthRoutes(mux *http.ServeMux) {
	// Do not put these under /api/auth/: that namespace bypasses ARTEX JWT auth.
	mux.HandleFunc("GET /api/llm/xai-oauth/status", s.xaiOAuthStatus)
	mux.HandleFunc("POST /api/llm/xai-oauth/login", s.xaiOAuthLogin)
	mux.HandleFunc("GET /api/llm/xai-oauth/login/{id}", s.xaiOAuthLoginStatus)
	mux.HandleFunc("DELETE /api/llm/xai-oauth/login/{id}", s.xaiOAuthCancel)
	mux.HandleFunc("POST /api/llm/xai-oauth/logout", s.xaiOAuthLogout)
}

func (s *Server) xaiOAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth := s.xaiAuth()
	if auth == nil {
		writeJSON(w, 200, xaioauth.Status{})
		return
	}
	status, err := auth.Status()
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, status)
}

func (s *Server) xaiOAuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth := s.xaiAuth()
	if auth == nil {
		writeErr(w, 503, "Grok subscription login is unavailable")
		return
	}
	s.xaiLogin.opMu.Lock()
	defer s.xaiLogin.opMu.Unlock()
	s.xaiLogin.mu.Lock()
	pending := s.xaiLogin.flow != nil && s.xaiLogin.flow.state == "pending"
	tooSoon := time.Since(s.xaiLogin.lastStart) < 5*time.Second
	if !pending && !tooSoon {
		s.xaiLogin.lastStart = time.Now()
	}
	s.xaiLogin.mu.Unlock()
	if pending {
		writeErr(w, 409, "A Grok login is already pending; finish or cancel it first")
		return
	}
	if tooSoon {
		w.Header().Set("Retry-After", "5")
		writeErr(w, 429, "Please wait before starting another Grok login")
		return
	}
	// A completed flow may still be reapplying its provider. Join it before
	// replacing the handle so a later logout can account for every worker.
	if err := s.cancelXAILogin(r.Context(), ""); err != nil {
		writeErr(w, 503, "Previous Grok login is still finishing")
		return
	}
	if s.xaiOAuthPath != "" {
		if err := ensureOAuthDirectory(s.xaiOAuthPath); err != nil {
			writeErr(w, 503, err.Error())
			return
		}
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	// Request cancellation applies during the initial exchange. After returning
	// a flow ID the background poll belongs to the server, not the HTTP request.
	stop := context.AfterFunc(r.Context(), cancel)
	device, err := auth.Start(ctx)
	stop()
	if err != nil {
		cancel()
		writeErr(w, 502, err.Error())
		return
	}
	if r.Context().Err() != nil || ctx.Err() != nil {
		cancel()
		writeErr(w, 408, "Grok login request was cancelled")
		return
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		cancel()
		writeErr(w, 500, "Cannot create Grok login identifier")
		return
	}
	flow := &xaiLogin{id: hex.EncodeToString(nonce[:]), state: "pending", cancel: cancel,
		done: make(chan struct{}), expires: device.ExpiresAt}
	s.xaiLogin.mu.Lock()
	s.xaiLogin.flow = flow
	s.xaiLogin.mu.Unlock()
	go s.waitForXAILogin(ctx, auth, flow, device)
	// Explicit safe fields: never serialize a provider's device code or tokens.
	writeJSON(w, 200, map[string]any{
		"flow_id": flow.id, "user_code": device.UserCode,
		"verification_uri":          device.VerificationURI,
		"verification_uri_complete": device.VerificationURIComplete,
		"expires_at":                device.ExpiresAt, "interval": device.IntervalSeconds,
	})
}

func (s *Server) waitForXAILogin(ctx context.Context, auth xaiFlowAuth, flow *xaiLogin, device *xaioauth.DeviceFlow) {
	defer close(flow.done)
	defer flow.cancel()
	err := auth.Wait(ctx, device)
	s.xaiLogin.mu.Lock()
	if ctx.Err() != nil {
		flow.state = "cancelled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || time.Now().After(flow.expires) {
			flow.state = "expired"
		}
	} else if err != nil {
		flow.state, flow.err = "error", err.Error()
		if errors.Is(err, xaioauth.ErrExpired) {
			flow.state = "expired"
		}
	} else {
		flow.state = "complete"
	}
	complete := flow.state == "complete"
	s.xaiLogin.mu.Unlock()
	if complete && s.m != nil && s.m.pg != nil {
		s.invalidateProfileAgents()
		s.reapplyActiveProfile()
	}
}

func (s *Server) xaiOAuthLoginStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s.xaiLogin.mu.Lock()
	defer s.xaiLogin.mu.Unlock()
	flow := s.xaiLogin.flow
	if flow == nil || flow.id != r.PathValue("id") {
		writeErr(w, 404, "Grok login not found")
		return
	}
	writeJSON(w, 200, map[string]any{"state": flow.state, "error": flow.err})
}

// Called with opMu held. Joining the worker closes the window in which logout
// could erase credentials just before an in-flight authorization saves them.
func (s *Server) cancelXAILogin(ctx context.Context, id string) error {
	s.xaiLogin.mu.Lock()
	flow := s.xaiLogin.flow
	if id != "" && (flow == nil || flow.id != id) {
		s.xaiLogin.mu.Unlock()
		return os.ErrNotExist
	}
	if flow == nil {
		s.xaiLogin.mu.Unlock()
		return nil
	}
	flow.cancel()
	s.xaiLogin.mu.Unlock()
	select {
	case <-flow.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) xaiOAuthCancel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s.xaiLogin.opMu.Lock()
	defer s.xaiLogin.opMu.Unlock()
	if err := s.cancelXAILogin(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeErr(w, 404, "Grok login not found")
		} else {
			writeErr(w, 503, "Grok login cancellation is still in progress")
		}
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) xaiOAuthLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth := s.xaiAuth()
	if auth == nil {
		writeErr(w, 503, "Grok subscription login is unavailable")
		return
	}
	s.xaiLogin.opMu.Lock()
	defer s.xaiLogin.opMu.Unlock()
	if err := s.cancelXAILogin(r.Context(), ""); err != nil {
		writeErr(w, 503, "Grok login cancellation is still in progress")
		return
	}
	if err := auth.Logout(r.Context()); err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	s.invalidateProfileAgents()
	s.clearSubscriptionRuntime()
	if s.m != nil && s.m.pg != nil {
		s.reapplyActiveProfile()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) clearSubscriptionRuntime() {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.llmCfg.IsSubscription() {
		s.llmOn = false
		s.llmProv, s.llmDirect, s.chatAgent = nil, nil, nil
	}
}

// Clear only transitions involving subscriptions; unrelated API-key edits
// retain the established behavior. Credentials or construction failures never
// authorize continuing on the previous billing source.
func (s *Server) clearInvalidSubscriptionTransition(next agent.Config) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if next.IsSubscription() || s.llmCfg.IsSubscription() {
		s.llmCfg = next
		s.llmOn = false
		s.llmProv, s.llmDirect, s.chatAgent = nil, nil, nil
	}
}

func validateXAIProxy(proxy string) error {
	if strings.TrimSpace(proxy) == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(proxy))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
		return errors.New("Grok proxy must use http://, https:// or socks5:// with a host")
	}
	return nil
}

func validateXAIProfile(baseURL, apiKey, sessionHeader string) error {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	baseURL = strings.TrimSuffix(baseURL, "/responses")
	if baseURL != "" && baseURL != xaioauth.APIBaseURL {
		return fmt.Errorf("Grok subscription requires %s", xaioauth.APIBaseURL)
	}
	if strings.TrimSpace(apiKey) != "" {
		return fmt.Errorf("Grok subscription uses browser OAuth; do not supply an API key or SSO cookie")
	}
	if strings.TrimSpace(sessionHeader) != "" {
		return fmt.Errorf("Grok subscription does not support a custom session header")
	}
	return nil
}

func (s *Server) xaiModels(w http.ResponseWriter, r *http.Request, baseURL, apiKey, proxy string) {
	if err := validateXAIProfile(baseURL, apiKey, ""); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if s.xaiOAuth == nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "请先登入 Grok 订阅"})
		return
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	if proxy = strings.TrimSpace(proxy); proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			writeErr(w, 400, "Invalid Grok outbound proxy")
			return
		}
		transport.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{Transport: s.xaiOAuth.Transport(transport), Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, xaioauth.APIBaseURL+"/models", nil)
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Authentication error bodies may echo credentials; never expose them.
		detail := fmt.Sprintf("Grok returned HTTP %d", resp.StatusCode)
		if resp.StatusCode == 403 {
			detail += ": subscription entitlement does not permit this API; no API-key fallback was used"
		}
		writeJSON(w, 200, map[string]any{"ok": false, "error": detail})
		return
	}
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "Invalid Grok model list response"})
		return
	}
	models := make([]string, 0, len(result.Data))
	for _, model := range result.Data {
		if model.ID != "" {
			models = append(models, model.ID)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "models": models})
}
