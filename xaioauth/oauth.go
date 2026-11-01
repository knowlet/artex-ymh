// Package xaioauth connects to xAI's subscription OAuth service. It deliberately
// has no API-key fallback and never returns credentials in a status response.
package xaioauth

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
	"strings"
	"time"
)

const (
	Provider     = "xai-oauth"
	APIBaseURL   = "https://api.x.ai/v1"
	DefaultModel = "grok-4.6"

	deviceEndpoint = "https://auth.x.ai/oauth2/device/code"
	tokenEndpoint  = "https://auth.x.ai/oauth2/token"
	publicClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	oauthScope     = "openid profile email offline_access grok-cli:access api:access"
	deviceGrant    = "urn:ietf:params:oauth:grant-type:device_code"
	maxAuthBody    = 128 * 1024
	refreshMargin  = 2 * time.Minute
)

var (
	ErrNotConnected   = errors.New("xAI subscription is not connected; sign in with Grok OAuth")
	ErrReauthRequired = errors.New("xAI OAuth session is no longer valid; sign in again")
	ErrEntitlement    = errors.New("xAI denied subscription access (HTTP 403); check the account's model entitlement; API-key billing is separate")
	ErrDenied         = errors.New("xAI device authorization was denied")
	ErrExpired        = errors.New("xAI device authorization expired; start a new sign-in")
	ErrSuperseded     = errors.New("xAI sign-in was cancelled, logged out, or replaced by a newer sign-in")
	ErrUnsafeStore    = errors.New("xAI credential storage must be a regular private file in a private directory, without symlinks")
	ErrUnsafeEndpoint = errors.New("xAI subscription credentials may only be sent to https://api.x.ai/v1/responses or /v1/models")
)

// DeviceFlow contains only display-safe JSON fields. The opaque device code and
// generation stay on the server and must never be passed to an LLM or a browser.
type DeviceFlow struct {
	UserCode                string    `json:"user_code"`
	VerificationURI         string    `json:"verification_uri"`
	VerificationURIComplete string    `json:"verification_uri_complete"`
	ExpiresAt               time.Time `json:"expires_at"`
	IntervalSeconds         int       `json:"interval"`
	DeviceCode              string    `json:"-"`
	generation              string
	storePath               string
}

func (f DeviceFlow) String() string { return "xAI OAuth device authorization (credentials redacted)" }

// Status describes local authentication only, not a live subscription/quota check.
type Status struct {
	Connected      bool      `json:"connected"`
	ExpiresAt      time.Time `json:"expires_at"`
	ReauthRequired bool      `json:"reauth_required"`
}

type tokenState struct {
	Version        int       `json:"version"`
	AccessToken    string    `json:"access_token,omitempty"`
	RefreshToken   string    `json:"refresh_token,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	ReauthRequired bool      `json:"reauth_required,omitempty"`
}

// Manager owns one deployment's local subscription session. Different managers
// and processes using the same path coordinate through a persistent OS file lock.
// The caller creates the credential directory (0700 on Unix) before Start.
type Manager struct {
	path     string
	clientID string
	client   *http.Client
	now      func() time.Time
	wait     func(context.Context, time.Duration) error
}

// NewManager does not access the filesystem or network. ARTEX_XAI_CLIENT_ID may
// select a separately registered public client; it is not a client secret.
func NewManager(path string) *Manager {
	clientID := strings.TrimSpace(os.Getenv("ARTEX_XAI_CLIENT_ID"))
	if clientID == "" {
		clientID = publicClientID
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Match ARTEX's explicit-proxy policy.
	return &Manager{
		path: path, clientID: clientID,
		client: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: rejectRedirect},
		now:    time.Now, wait: sleepContext,
	}
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func sleepContext(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Start obtains a fresh device code. An existing session continues working until
// the new login succeeds. Starting a newer login invalidates older pending flows.
func (m *Manager) Start(ctx context.Context) (*DeviceFlow, error) {
	var generation string
	err := m.withLock(ctx, func(lock *os.File) error {
		var err error
		generation, err = newGeneration(lock)
		return err
	})
	if err != nil {
		return nil, err
	}
	var response struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := m.postForm(ctx, deviceEndpoint, url.Values{"client_id": {m.clientID}, "scope": {oauthScope}}, &response); err != nil {
		return nil, err
	}
	if !validSecret(response.DeviceCode) || response.UserCode == "" || len(response.UserCode) > 256 || response.ExpiresIn <= 0 || response.ExpiresIn > 86400 {
		return nil, errors.New("xAI returned an invalid device authorization response")
	}
	if response.Interval == 0 {
		response.Interval = 5
	}
	if response.Interval < 1 || response.Interval > 3600 {
		return nil, errors.New("xAI returned an invalid polling interval")
	}
	if !validVerificationURL(response.VerificationURI) {
		return nil, errors.New("xAI returned an unsafe verification URL")
	}
	if response.VerificationURIComplete == "" {
		response.VerificationURIComplete = response.VerificationURI
	}
	if !validVerificationURL(response.VerificationURIComplete) {
		return nil, errors.New("xAI returned an unsafe verification URL")
	}
	flow := &DeviceFlow{
		DeviceCode: response.DeviceCode, UserCode: response.UserCode,
		VerificationURI: response.VerificationURI, VerificationURIComplete: response.VerificationURIComplete,
		ExpiresAt: m.now().Add(time.Duration(response.ExpiresIn) * time.Second), IntervalSeconds: response.Interval,
		generation: generation, storePath: m.path,
	}
	if err := m.checkFlow(ctx, flow); err != nil {
		return nil, err
	}
	return flow, nil
}

func validVerificationURL(raw string) bool {
	if len(raw) > 8192 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Fragment == "" && (u.Port() == "" || u.Port() == "443") &&
		(u.Hostname() == "accounts.x.ai" || u.Hostname() == "auth.x.ai")
}

// Wait follows RFC 8628, respecting the advertised interval and adding five
// seconds on slow_down. Polling and persistence both stop when ctx is cancelled.
func (m *Manager) Wait(ctx context.Context, flow *DeviceFlow) error {
	if flow == nil || flow.generation == "" || flow.storePath != m.path || !validSecret(flow.DeviceCode) || flow.IntervalSeconds < 1 || flow.IntervalSeconds > 3600 {
		return errors.New("invalid xAI device authorization flow")
	}
	interval := time.Duration(flow.IntervalSeconds) * time.Second
	for {
		if err := m.checkFlow(ctx, flow); err != nil {
			return err
		}
		remaining := flow.ExpiresAt.Sub(m.now())
		if remaining <= 0 {
			return ErrExpired
		}
		if err := m.wait(ctx, min(interval, remaining)); err != nil {
			return err
		}
		if !m.now().Before(flow.ExpiresAt) {
			return ErrExpired
		}
		if err := m.checkFlow(ctx, flow); err != nil {
			return err
		}
		var response tokenResponse
		pollCtx, cancel := context.WithTimeout(ctx, min(20*time.Second, flow.ExpiresAt.Sub(m.now())))
		err := m.postForm(pollCtx, tokenEndpoint, url.Values{"client_id": {m.clientID}, "grant_type": {deviceGrant}, "device_code": {flow.DeviceCode}}, &response)
		cancel()
		var authErr *endpointError
		if errors.As(err, &authErr) {
			switch authErr.code {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += 5 * time.Second
				continue
			case "access_denied":
				return ErrDenied
			case "expired_token":
				return ErrExpired
			}
		}
		if err != nil {
			return err
		}
		state, err := response.state(m.now(), "")
		if err != nil {
			return err
		}
		return m.withLock(ctx, func(lock *os.File) error {
			if err := sameGeneration(lock, flow.generation); err != nil {
				return err
			}
			if !m.now().Before(flow.ExpiresAt) {
				return ErrExpired
			}
			return m.save(ctx, state)
		})
	}
}

func (m *Manager) checkFlow(ctx context.Context, flow *DeviceFlow) error {
	return m.withLock(ctx, func(lock *os.File) error { return sameGeneration(lock, flow.generation) })
}

// Token returns a current bearer, refreshing inside a two-minute expiry margin.
func (m *Manager) Token(ctx context.Context) (string, error) { return m.token(ctx, "", false) }

// Refresh retries authentication after a 401. If another caller already rotated
// the rejected access token, its replacement is reused without another refresh.
func (m *Manager) Refresh(ctx context.Context, rejectedToken string) (string, error) {
	return m.token(ctx, rejectedToken, true)
}

func (m *Manager) token(ctx context.Context, rejectedToken string, force bool) (string, error) {
	var token string
	err := m.withLock(ctx, func(_ *os.File) error {
		state, err := m.load()
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotConnected
		}
		if err != nil {
			return err
		}
		if state.ReauthRequired {
			return ErrReauthRequired
		}
		if force && rejectedToken != "" && state.AccessToken != rejectedToken && m.now().Before(state.ExpiresAt) {
			token = state.AccessToken
			return nil
		}
		if !force && m.now().Add(refreshMargin).Before(state.ExpiresAt) {
			token = state.AccessToken
			return nil
		}
		var response tokenResponse
		err = m.postForm(ctx, tokenEndpoint, url.Values{"client_id": {m.clientID}, "grant_type": {"refresh_token"}, "refresh_token": {state.RefreshToken}}, &response)
		var authErr *endpointError
		if errors.As(err, &authErr) && (authErr.code == "invalid_grant" || authErr.status == 401) {
			// A revoked/single-use grant must not be replayed indefinitely.
			if saveErr := m.save(context.WithoutCancel(ctx), tokenState{Version: 1, ReauthRequired: true}); saveErr != nil {
				return saveErr
			}
			return ErrReauthRequired
		}
		if err != nil {
			return err
		}
		updated, err := response.state(m.now(), state.RefreshToken)
		if err != nil {
			return err
		}
		// The server already consumed the single-use refresh token. Persist its
		// replacement even if the caller cancelled while the response arrived.
		// Logout waits for this same lock, then removes the new state normally.
		if err := m.save(context.WithoutCancel(ctx), updated); err != nil {
			return err
		}
		token = updated.AccessToken
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotConnected
	}
	if err == nil && ctx.Err() != nil {
		return "", ctx.Err()
	}
	return token, err
}

// Status reads local state without network requests or token refresh.
func (m *Manager) Status() (Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var status Status
	err := m.withLock(ctx, func(_ *os.File) error {
		state, err := m.load()
		if err != nil {
			return err
		}
		status = Status{Connected: !state.ReauthRequired, ExpiresAt: state.ExpiresAt, ReauthRequired: state.ReauthRequired}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return Status{}, nil
	}
	return status, err
}

// Logout clears local credentials and invalidates pending login flows. It does
// not revoke the upstream account grant; revoke that in xAI account settings.
func (m *Manager) Logout(ctx context.Context) error {
	err := m.withLock(ctx, func(lock *os.File) error {
		if _, err := newGeneration(lock); err != nil {
			return err
		}
		if _, err := privateFile(m.path); err != nil {
			return err
		}
		if err := os.Remove(m.path); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(m.path))
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func validSecret(v string) bool {
	return v != "" && len(v) <= 32768 && !strings.ContainsAny(v, "\r\n\x00")
}

func (r tokenResponse) state(now time.Time, oldRefresh string) (tokenState, error) {
	if r.RefreshToken == "" {
		r.RefreshToken = oldRefresh
	}
	if !validSecret(r.AccessToken) || !validSecret(r.RefreshToken) || r.ExpiresIn < 1 || r.ExpiresIn > 366*86400 || (r.TokenType != "" && !strings.EqualFold(r.TokenType, "Bearer")) {
		return tokenState{}, errors.New("xAI returned an invalid OAuth token response")
	}
	return tokenState{Version: 1, AccessToken: r.AccessToken, RefreshToken: r.RefreshToken, ExpiresAt: now.Add(time.Duration(r.ExpiresIn) * time.Second)}, nil
}

type endpointError struct {
	status int
	code   string
}

func (e *endpointError) Error() string {
	if e.status == http.StatusForbidden {
		return ErrEntitlement.Error()
	}
	if e.status == http.StatusTooManyRequests {
		return "xAI OAuth rate limit reached; wait before trying again"
	}
	return fmt.Sprintf("xAI OAuth request failed (HTTP %d)", e.status)
}
func (e *endpointError) Is(target error) bool {
	return target == ErrEntitlement && e.status == http.StatusForbidden
}

func (m *Manager) postForm(ctx context.Context, endpoint string, form url.Values, output any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("could not build xAI authorization request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	client := *m.client
	client.CheckRedirect = rejectRedirect
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("xAI authorization service is unavailable or timed out")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthBody+1))
	if err != nil || len(body) > maxAuthBody {
		return errors.New("xAI returned an unreadable or oversized authorization response")
	}
	if resp.StatusCode != http.StatusOK {
		var data struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &data)
		return &endpointError{status: resp.StatusCode, code: data.Error}
	}
	if err := json.Unmarshal(body, output); err != nil {
		return errors.New("xAI returned malformed authorization data")
	}
	return nil
}

func newGeneration(lock *os.File) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", errors.New("could not create xAI sign-in generation")
	}
	generation := hex.EncodeToString(random[:])
	if err := lock.Truncate(0); err != nil {
		return "", err
	}
	if _, err := lock.WriteAt([]byte(generation), 0); err != nil {
		return "", err
	}
	if err := lock.Sync(); err != nil {
		return "", err
	}
	return generation, nil
}

func sameGeneration(lock *os.File, expected string) error {
	data := make([]byte, 33)
	n, err := lock.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if n != 32 || string(data[:n]) != expected {
		return ErrSuperseded
	}
	return nil
}
