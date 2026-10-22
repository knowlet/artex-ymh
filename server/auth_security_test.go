package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSecurityTicketsOnlyAuthenticateGETStreams(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/settings", 401}, {"POST", "/api/tasks", 401},
		{"DELETE", "/api/tasks/1", 401}, {"POST", "/api/logs/stream", 401},
		{"GET", "/api/logs/stream", 200}, {"GET", "/api/update/stream", 200},
		{"GET", "/api/exploration/activity/stream", 200},
		{"GET", "/api/side-questions/abc/events", 200},
		{"GET", "/api/side-questions/abc/extra/events", 401},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			s := &Server{jwtKey: testJWTKey, authkv: newMemKV()}
			ticket, err := s.tickets.issue()
			if err != nil {
				t.Fatal(err)
			}
			h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path+"?ticket="+ticket, nil))
			if w.Code != tc.want {
				t.Fatalf("ticket accepted outside GET SSE boundary: got %d want %d", w.Code, tc.want)
			}
		})
	}
}

// barrierKV makes both refresh requests finish validation before either can
// delete the old token. This reproduces the read/delete race deterministically.
type barrierKV struct {
	*memKV
	ready sync.WaitGroup
}

func (k *barrierKV) DeleteSetting(key string) error {
	if strings.HasPrefix(key, "auth.refresh.") {
		k.ready.Done()
		k.ready.Wait()
	}
	return k.memKV.DeleteSetting(key)
}
func TestSecurityConcurrentRefreshHasOneWinner(t *testing.T) {
	kv := &barrierKV{memKV: newMemKV()}
	kv.ready.Add(2)
	token, err := issueRefreshToken(kv, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{jwtKey: testJWTKey, authkv: kv}
	codes := make(chan int, 2)
	for range 2 {
		go func() {
			r := httptest.NewRequest("POST", "/api/auth/refresh", nil)
			r.AddCookie(cookieFor(token))
			w := httptest.NewRecorder()
			s.authRefresh(w, r)
			codes <- w.Code
		}()
	}
	a, b := <-codes, <-codes
	if !((a == 200 && b == 401) || (a == 401 && b == 200)) {
		t.Fatalf("one refresh must win: got %d and %d", a, b)
	}
}

func TestSecurityRefreshStoreFailureDoesNotIssueSession(t *testing.T) {
	kv := newMemKV()
	s := &Server{jwtKey: testJWTKey, authkv: kv}
	kv.err = errTest
	r := httptest.NewRequest("POST", "/api/auth/refresh", nil)
	r.AddCookie(cookieFor("synthetic-refresh"))
	w := httptest.NewRecorder()
	s.authRefresh(w, r)
	if w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("store failure issued credentials: status=%d cookies=%v", w.Code, w.Result().Cookies())
	}
}

type authDeadlineWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *authDeadlineWriter) SetReadDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}
func TestSecurityAuthDecodeBoundsAndDeadline(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"password":"ok"}`, 200},
		{`{"password":"ok"} {}`, 400},
		{`{"password":"` + strings.Repeat("x", 5000) + `"}`, 413},
		{`{"password":"ok"}` + strings.Repeat(" ", 5000), 413},
	} {
		w := &authDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
		r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(tc.body))
		var req struct {
			Password string `json:"password"`
		}
		if decodeAuth(w, r, &req) {
			w.WriteHeader(200)
		}
		if w.Code != tc.want {
			t.Fatalf("decode status=%d want=%d", w.Code, tc.want)
		}
		if len(w.deadlines) != 2 || w.deadlines[0].IsZero() || !w.deadlines[1].IsZero() {
			t.Fatalf("read deadline not set then cleared: %v", w.deadlines)
		}
	}
}

// Exercise both script dispatch paths without connecting to a database. Actual
// transaction/revocation semantics are covered by the opt-in PostgreSQL test.
func TestSecurityResetScriptSQLContract(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	for _, mode := range []string{"local", "docker"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			capture := filepath.Join(dir, "sql")
			for _, name := range []string{"psql", "docker"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\ncat > \"$ARTEX_TEST_SQL_CAPTURE\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(bash, "../reset-password.sh", "-m", mode, "--exec", "docker", "-U", "fixture", "-d", "fixture", "-p", "synthetic-test-password", "-y")
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "ARTEX_TEST_SQL_CAPTURE="+capture)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("script: %v: %s", err, output)
			}
			raw, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			sql := string(raw)
			prior := -1
			for _, part := range []string{"BEGIN;", "VALUES ('auth.password_hash'", "VALUES ('auth.key_version', '1')", "DELETE FROM settings WHERE key LIKE 'auth.refresh.%';", "COMMIT;"} {
				at := strings.Index(sql, part)
				if at < 0 || at <= prior {
					t.Fatalf("reset SQL missing/out of order %q", part)
				}
				prior = at
			}
			if !strings.Contains(sql, `\set ON_ERROR_STOP on`) {
				t.Fatal("script does not stop on SQL errors")
			}
		})
	}
}
