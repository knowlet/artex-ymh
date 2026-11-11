package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Autumn-27/artex/config"
)

// TestAdvisoryE2EServeForPlaywright starts a real HTTP stack for browser E2E (fake LLM only).
// Run: ARTEX_E2E_SERVE=1 ARTEX_AUTH_TEST_DSN=... go test ./server -run TestAdvisoryE2EServeForPlaywright -count=1 -timeout=30m
func TestAdvisoryE2EServeForPlaywright(t *testing.T) {
	if os.Getenv("ARTEX_E2E_SERVE") == "" {
		t.Skip("ARTEX_E2E_SERVE unset")
	}
	dsn := os.Getenv("ARTEX_AUTH_TEST_DSN")
	if dsn == "" {
		t.Fatal("ARTEX_AUTH_TEST_DSN required")
	}
	if err := os.Setenv("ARTEX_PG_DSN", dsn); err != nil {
		t.Fatal(err)
	}
	addr := envDefault("ADVISORY_E2E_ADDR", "127.0.0.1:9877")
	envPath := envDefault("ADVISORY_E2E_ENV_FILE", filepath.Join(os.TempDir(), "artex-advisory-e2e.env"))

	dataDir := t.TempDir()
	mgr, err := NewManager(dataDir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	skillDir := config.SkillDir()
	srv := New(ctx, mgr, skillDir, dataDir, config.BaseDir())
	srv.jwtKey = testJWTKey

	fake := &advisoryFake{text: advisoryFixtureReply}
	token, autoPendingID, cancelPendingID, err := srv.AdvisoryE2EBootstrap(ctx, fake, "e2e-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteAdvisoryE2EEnv(envPath, "http://"+addr, token, autoPendingID, cancelPendingID); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(map[string]any{
		"baseURL": "http://" + addr, "token": token, "pendingID": autoPendingID, "cancelPendingID": cancelPendingID, "envFile": envPath,
	})
	fmt.Println("ADVISORY_E2E_META=" + string(meta))

	httpSrv := &http.Server{Addr: addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("[advisory-e2e] listening on http://%s auto_pending=%d cancel_pending=%d", addr, autoPendingID, cancelPendingID)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[advisory-e2e] serve: %v", err)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
