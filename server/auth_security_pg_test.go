package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This suite never uses the application's DSN/config. Point this explicit
// opt-in only at a disposable test PostgreSQL; every test uses a fresh schema.
func authSecurityPG(t *testing.T) (*Server, string) {
	t.Helper()
	dsn := os.Getenv("ARTEX_AUTH_TEST_DSN")
	if dsn == "" {
		t.Skip("ARTEX_AUTH_TEST_DSN is unset; isolated PostgreSQL test not run")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid isolated PostgreSQL configuration")
	}
	admin := stdlib.OpenDB(*cfg)
	schema := fmt.Sprintf("auth_security_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema + ",public"
	pool := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { pool.Close(); admin.Exec("DROP SCHEMA " + schema + " CASCADE"); admin.Close() })
	if _, err = pool.Exec(`CREATE TABLE settings(key text PRIMARY KEY,value text NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	return &Server{jwtKey: testJWTKey, m: &Manager{pg: &db.DB{DB: pool}}}, schema
}

func TestSecurityPGBootstrapOneWinner(t *testing.T) {
	s, _ := authSecurityPG(t)
	const n = 8
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, n)
	var ready sync.WaitGroup
	ready.Add(n)
	for i := range n {
		go func(i int) {
			ready.Done()
			<-start
			r := httptest.NewRequest("POST", "/api/auth/init", strings.NewReader(fmt.Sprintf(`{"password":"isolated-password-%d"}`, i)))
			w := httptest.NewRecorder()
			s.authInit(w, r)
			results <- w
		}(i)
	}
	ready.Wait()
	close(start)
	winners := 0
	for range n {
		w := <-results
		if w.Code == 200 {
			winners++
			var out struct {
				Token string `json:"token"`
			}
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || !s.validAccessToken(out.Token) {
				t.Fatal("winner did not receive valid token")
			}
		} else if w.Code != 403 {
			t.Fatalf("unexpected init status %d: %s", w.Code, w.Body.String())
		}
	}
	if winners != 1 {
		t.Fatalf("bootstrap granted %d sessions, want exactly one", winners)
	}
}

func TestSecurityPGAuthBodyLimit(t *testing.T) {
	s, _ := authSecurityPG(t)
	for _, body := range []string{`{"password":"` + strings.Repeat("x", 5000) + `"}`, `{"password":"fine","ignored":"` + strings.Repeat("x", 5000) + `"}`, `{"password":"fine"}` + strings.Repeat(" ", 5000)} {
		w := httptest.NewRecorder()
		s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", strings.NewReader(body)))
		if w.Code != 413 {
			t.Fatalf("unbounded auth body: got %d want 413", w.Code)
		}
	}
	if _, ok, err := s.m.pg.GetSetting(authPassKey); err != nil || ok {
		t.Fatalf("oversized request wrote password: present=%v err=%v", ok, err)
	}
}

func TestSecurityPGResetRevokesAndRollsBack(t *testing.T) {
	s, schema := authSecurityPG(t)
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql unavailable")
	}
	// Install pgcrypto before selecting the isolated schema, as in a deployment.
	if _, err := s.m.pg.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public"); err != nil {
		t.Fatal(err)
	}
	kv := s.m.pg
	if err := kv.SetSetting(authPassKey, "old-test-hash"); err != nil {
		t.Fatal(err)
	}
	token, err := signJWT(s.jwtKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issueRefreshToken(kv, 0)
	if err != nil {
		t.Fatal(err)
	}
	run := func() error {
		cmd := exec.CommandContext(context.Background(), "bash", filepath.Join("..", "reset-password.sh"), "-m", "local", "--dsn", os.Getenv("ARTEX_AUTH_TEST_DSN"), "-p", "isolated-test-password", "-y")
		cmd.Env = append(os.Environ(), "PGOPTIONS=-c search_path="+schema+",public")
		return cmd.Run()
	}
	if err := run(); err != nil {
		t.Fatal("reset script failed:", err)
	}
	if s.validAccessToken(token) {
		t.Error("pre-reset access token remains valid")
	}
	ver, ok := authKeyVersion(kv)
	if !ok || ver != 1 {
		t.Errorf("version=%d readable=%v, want 1", ver, ok)
	}
	if _, ok := validateRefreshToken(kv, refresh, ver); ok {
		t.Error("pre-reset refresh token remains valid")
	}
	var count int
	if err := kv.QueryRow("SELECT count(*) FROM settings WHERE key LIKE 'auth.refresh.%'").Scan(&count); err != nil || count != 0 {
		t.Errorf("refresh records=%d err=%v", count, err)
	}
	before, _, _ := kv.GetSetting(authPassKey)
	if err := kv.SetSetting(authKeyVersionKey, "invalid-test-version"); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Error("reset should fail on corrupt version")
	}
	after, _, _ := kv.GetSetting(authPassKey)
	if after != before {
		t.Error("password changed despite revocation failure; transaction did not roll back")
	}
}
