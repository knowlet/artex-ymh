package xaioauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
func testManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m := NewManager(filepath.Join(dir, "session.json"))
	m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("unexpected HTTP request")
		return nil, errors.New("unexpected request")
	})
	return m
}
func saveFixture(t *testing.T, m *Manager, expiresAt time.Time) {
	t.Helper()
	if err := m.withLock(context.Background(), func(*os.File) error {
		return m.save(context.Background(), tokenState{Version: 1, AccessToken: "fixture-access", RefreshToken: "fixture-refresh", ExpiresAt: expiresAt})
	}); err != nil {
		t.Fatal(err)
	}
}

const validDeviceJSON = `{"device_code":"fixture-device-secret","user_code":"ABCD-EFGH","verification_uri":"https://accounts.x.ai/oauth2/device","expires_in":1800,"interval":5}`
const validTokenJSON = `{"access_token":"fixture-access-new","refresh_token":"fixture-refresh-new","token_type":"Bearer","expires_in":3600}`

func TestDeviceFlowPendingSlowDownAndPrivatePersistence(t *testing.T) {
	m := testManager(t)
	now := time.Now().UTC()
	m.now = func() time.Time { return now }
	var waits []time.Duration
	m.wait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		now = now.Add(d)
		return ctx.Err()
	}
	var polls int
	m.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatal("incorrect OAuth request")
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.Form.Get("client_id") != publicClientID {
			t.Fatal("wrong public client")
		}
		if req.URL.String() == deviceEndpoint {
			if req.Form.Get("scope") != oauthScope {
				t.Fatal("wrong scope")
			}
			return jsonResponse(200, validDeviceJSON), nil
		}
		if req.URL.String() != tokenEndpoint || req.Form.Get("grant_type") != deviceGrant || req.Form.Get("device_code") != "fixture-device-secret" {
			t.Fatal("incorrect token exchange")
		}
		polls++
		switch polls {
		case 1:
			return jsonResponse(400, `{"error":"authorization_pending"}`), nil
		case 2:
			return jsonResponse(400, `{"error":"slow_down"}`), nil
		default:
			return jsonResponse(200, validTokenJSON), nil
		}
	})
	flow, err := m.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if flow.VerificationURIComplete != flow.VerificationURI {
		t.Fatal("optional complete URI fallback missing")
	}
	encoded, _ := json.Marshal(flow)
	if strings.Contains(string(encoded), "fixture-device-secret") || strings.Contains(string(encoded), "generation") {
		t.Fatal("device secret escaped in JSON")
	}
	if err := m.Wait(context.Background(), flow); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 3 || waits[0] != 5*time.Second || waits[1] != 5*time.Second || waits[2] != 10*time.Second {
		t.Fatalf("incorrect RFC polling intervals: %v", waits)
	}
	state, err := m.Status()
	if err != nil || !state.Connected || state.ReauthRequired {
		t.Fatalf("status: %+v, %v", state, err)
	}
	info, err := os.Stat(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("credentials mode %o", info.Mode().Perm())
	}
	data, _ := json.Marshal(state)
	if strings.Contains(string(data), "fixture-") {
		t.Fatal("status leaked tokens")
	}
	entries, _ := os.ReadDir(filepath.Dir(m.path))
	if len(entries) != 2 {
		t.Fatalf("temporary credential files left behind: %d", len(entries))
	}
}

func TestDeviceFlowErrorsAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       error
	}{{"denied", `{"error":"access_denied"}`, ErrDenied}, {"expired", `{"error":"expired_token"}`, ErrExpired}} {
		t.Run(tc.name, func(t *testing.T) {
			m := testManager(t)
			m.wait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
			m.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == deviceEndpoint {
					return jsonResponse(200, validDeviceJSON), nil
				}
				return jsonResponse(400, tc.body), nil
			})
			flow, err := m.Start(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Wait(context.Background(), flow); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if _, err := os.Stat(m.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed login persisted credentials")
			}
		})
	}
	t.Run("cancel-before-start", func(t *testing.T) {
		m := testManager(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := m.Start(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("expiry-bounds-wait", func(t *testing.T) {
		m := testManager(t)
		now := time.Now()
		m.now = func() time.Time { return now }
		m.wait = func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil }
		m.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != deviceEndpoint {
				t.Fatal("polled expired code")
			}
			return jsonResponse(200, strings.Replace(validDeviceJSON, `"expires_in":1800`, `"expires_in":2`, 1)), nil
		})
		flow, err := m.Start(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Wait(context.Background(), flow); !errors.Is(err, ErrExpired) {
			t.Fatal(err)
		}
	})
}

func TestUnsafeVerificationURLsRejected(t *testing.T) {
	for _, uri := range []string{"http://accounts.x.ai/oauth2/device", "https://accounts.x.ai.evil.test/oauth2/device", "https://evil.test/oauth2/device", "https://user:pass@accounts.x.ai/oauth2/device", "https://accounts.x.ai:444/oauth2/device"} {
		t.Run(uri, func(t *testing.T) {
			m := testManager(t)
			m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(200, strings.Replace(validDeviceJSON, "https://accounts.x.ai/oauth2/device", uri, 1)), nil
			})
			if _, err := m.Start(context.Background()); err == nil {
				t.Fatal("unsafe URL accepted")
			}
		})
	}
}

func TestLogoutAndNewLoginInvalidatePendingFlow(t *testing.T) {
	for _, action := range []string{"logout", "new-login"} {
		t.Run(action, func(t *testing.T) {
			m := testManager(t)
			m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, validDeviceJSON), nil })
			flow, err := m.Start(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			other := NewManager(m.path)
			other.client = m.client
			if action == "logout" {
				err = other.Logout(context.Background())
			} else {
				_, err = other.Start(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Wait(context.Background(), flow); !errors.Is(err, ErrSuperseded) {
				t.Fatalf("stale login was accepted: %v", err)
			}
		})
	}
}

func TestLogoutDuringExchangeCannotResurrectSession(t *testing.T) {
	m := testManager(t)
	m.wait = func(context.Context, time.Duration) error { return nil }
	started := make(chan struct{})
	release := make(chan struct{})
	m.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == deviceEndpoint {
			return jsonResponse(200, validDeviceJSON), nil
		}
		close(started)
		<-release
		return jsonResponse(200, validTokenJSON), nil
	})
	flow, err := m.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- m.Wait(context.Background(), flow) }()
	<-started
	if err := NewManager(m.path).Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrSuperseded) {
		t.Fatalf("got %v", err)
	}
	status, err := m.Status()
	if err != nil || status.Connected {
		t.Fatalf("resurrected session: %+v %v", status, err)
	}
}

func TestConcurrentRefreshUsesSingleRotatedGrant(t *testing.T) {
	m := testManager(t)
	saveFixture(t, m, time.Now().Add(time.Minute))
	var requests atomic.Int32
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.ParseForm(); err != nil {
			t.Error(err)
		}
		if req.Form.Get("grant_type") != "refresh_token" || req.Form.Get("refresh_token") != "fixture-refresh" {
			t.Error("replayed or incorrect refresh grant")
		}
		requests.Add(1)
		return jsonResponse(200, validTokenJSON), nil
	})
	var group sync.WaitGroup
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			other := NewManager(m.path)
			other.client.Transport = transport
			token, err := other.Token(context.Background())
			if err != nil || token != "fixture-access-new" {
				t.Errorf("token resolution failed: %v", err)
			}
		}()
	}
	group.Wait()
	if requests.Load() != 1 {
		t.Fatalf("refresh count = %d", requests.Load())
	}
	other := NewManager(m.path)
	other.client.Transport = transport
	if token, err := other.Refresh(context.Background(), "fixture-access"); err != nil || token != "fixture-access-new" {
		t.Fatalf("did not reuse replacement: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatal("concurrent stale 401 caused another rotation")
	}
}

func TestInvalidGrantQuarantinesAndRedacts(t *testing.T) {
	m := testManager(t)
	saveFixture(t, m, time.Now().Add(-time.Minute))
	var calls int
	m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(400, `{"error":"invalid_grant","error_description":"fixture-refresh sensitive provider details"}`), nil
	})
	for range 2 {
		if _, err := m.Token(context.Background()); !errors.Is(err, ErrReauthRequired) || strings.Contains(err.Error(), "fixture-") {
			t.Fatalf("incorrect or unredacted error: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("dead refresh replayed %d times", calls)
	}
	status, err := m.Status()
	if err != nil || status.Connected || !status.ReauthRequired {
		t.Fatalf("quarantine status %+v %v", status, err)
	}
	body, _ := os.ReadFile(m.path)
	if strings.Contains(string(body), "fixture-") {
		t.Fatal("dead credentials remain in store")
	}
}

func TestEntitlementFailureDoesNotDeleteSessionOrFallback(t *testing.T) {
	t.Setenv("XAI_API_KEY", "do-not-use-api-key")
	m := testManager(t)
	saveFixture(t, m, time.Now().Add(-time.Minute))
	m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(403, `{"error":"forbidden","message":"fixture-refresh"}`), nil
	})
	_, err := m.Token(context.Background())
	if !errors.Is(err, ErrEntitlement) || strings.Contains(err.Error(), "fixture-refresh") {
		t.Fatalf("got %v", err)
	}
	state, err := m.load()
	if err != nil || state.RefreshToken != "fixture-refresh" {
		t.Fatal("entitlement denial deleted valid grant")
	}
}

func TestCancellationAfterRefreshPersistsRotation(t *testing.T) {
	m := testManager(t)
	saveFixture(t, m, time.Now().Add(-time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { cancel(); return jsonResponse(200, validTokenJSON), nil })
	if _, err := m.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	state, err := m.load()
	if err != nil || state.RefreshToken != "fixture-refresh-new" {
		t.Fatal("cancellation discarded rotated grant")
	}
}

func TestMissingAndUnsafeCredentialStores(t *testing.T) {
	t.Run("missing-parent", func(t *testing.T) {
		m := NewManager(filepath.Join(t.TempDir(), "absent", "session.json"))
		s, err := m.Status()
		if err != nil || s.Connected {
			t.Fatal(s, err)
		}
		if err := m.Logout(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		m := testManager(t)
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, m.path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := m.Status(); !errors.Is(err, ErrUnsafeStore) {
			t.Fatal(err)
		}
		if err := m.Logout(context.Background()); !errors.Is(err, ErrUnsafeStore) {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(outside)
		if string(b) != "untouched" {
			t.Fatal("followed symlink")
		}
	})
	t.Run("directory", func(t *testing.T) {
		m := testManager(t)
		if err := os.Mkdir(m.path, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Status(); !errors.Is(err, ErrUnsafeStore) {
			t.Fatal(err)
		}
	})
	t.Run("world-readable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Unix modes")
		}
		m := testManager(t)
		saveFixture(t, m, time.Now().Add(time.Hour))
		if err := os.Chmod(m.path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Token(context.Background()); !errors.Is(err, ErrUnsafeStore) {
			t.Fatal(err)
		}
	})
	t.Run("unprivate-parent", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Unix modes")
		}
		m := testManager(t)
		if err := os.Chmod(filepath.Dir(m.path), 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Start(context.Background()); !errors.Is(err, ErrUnsafeStore) {
			t.Fatal(err)
		}
	})
}

func TestLockWaitHonorsCancellation(t *testing.T) {
	m := testManager(t)
	ready := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- m.withLock(context.Background(), func(*os.File) error { close(ready); <-release; return nil })
	}()
	<-ready
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := NewManager(m.path).Token(ctx)
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock ignored cancellation: %v", err)
	}
}

func TestLockAcrossProcesses(t *testing.T) {
	if path := os.Getenv("ARTEX_XAI_TEST_LOCK_PATH"); path != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
		defer cancel()
		err := NewManager(path).withLock(ctx, func(*os.File) error { return nil })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("child bypassed the parent process lock: %v", err)
		}
		return
	}
	m := testManager(t)
	err := m.withLock(context.Background(), func(*os.File) error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLockAcrossProcesses$", "-test.count=1")
		cmd.Env = append(os.Environ(), "ARTEX_XAI_TEST_LOCK_PATH="+m.path)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("lock helper failed: %s", output)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDevicePollingCancellationDoesNotSave(t *testing.T) {
	m := testManager(t)
	m.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != deviceEndpoint {
			t.Fatal("cancelled poll made an HTTP request")
		}
		return jsonResponse(200, validDeviceJSON), nil
	})
	flow, err := m.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.wait = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	if err := m.Wait(ctx, flow); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	status, err := m.Status()
	if err != nil || status.Connected {
		t.Fatalf("cancelled login persisted: %+v %v", status, err)
	}
}

func TestAuthRedirectsAndMalformedTokensFailClosed(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		m := testManager(t)
		var calls int
		m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			r := jsonResponse(307, "")
			r.Header.Set("Location", "https://evil.test/steal")
			return r, nil
		})
		if _, err := m.Start(context.Background()); err == nil {
			t.Fatal("accepted redirect")
		}
		if calls != 1 {
			t.Fatal("followed authorization redirect")
		}
	})
	for _, body := range []string{`{}`, `{"access_token":"ok","refresh_token":"ok","expires_in":0}`, `{"access_token":"ok","refresh_token":"ok","expires_in":3600,"token_type":"Basic"}`, `not-json`} {
		t.Run(body, func(t *testing.T) {
			m := testManager(t)
			saveFixture(t, m, time.Now().Add(-time.Minute))
			m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, body), nil })
			if _, err := m.Token(context.Background()); err == nil {
				t.Fatal("accepted malformed token response")
			}
		})
	}
}
