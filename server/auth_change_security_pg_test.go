package server

import (
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestSecurityPGPasswordChangeCommitsRevocation(t *testing.T) {
	s, _ := authSecurityPG(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("synthetic-old-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	access, _ := signJWT(s.jwtKey, 0)
	refresh, err := issueRefreshToken(s.m.pg, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(`{"old_password":"synthetic-old-password","new_password":"synthetic-new-password"}`))
	r.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	s.authChangePassword(w, r)
	if w.Code != 200 {
		t.Fatalf("password change: %d %s", w.Code, w.Body.String())
	}
	got, _, err := s.m.pg.GetSetting(authPassKey)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(got), []byte("synthetic-new-password")) != nil {
		t.Fatal("new password did not commit")
	}
	if s.validAccessToken(access) {
		t.Fatal("pre-change access token remains valid")
	}
	if _, ok, err := s.m.pg.GetSetting(refreshSettingKey(hashRefreshToken(refresh))); err != nil || ok {
		t.Fatal("pre-change refresh record remains")
	}
}

func TestSecurityPGPasswordChangeRollback(t *testing.T) {
	if os.Getenv("ARTEX_AUTH_TEST_DSN") == "" {
		t.Skip("ARTEX_AUTH_TEST_DSN is unset; isolated PostgreSQL test not run")
	}
	for _, failure := range []string{"corrupt-version", "version-write-failure"} {
		t.Run(failure, func(t *testing.T) {
			s, _ := authSecurityPG(t)
			pg := s.m.pg
			if err := pg.SetSetting(authPassKey, "synthetic-original-hash"); err != nil {
				t.Fatal(err)
			}
			version := "0"
			if failure == "corrupt-version" {
				version = "invalid-version"
			}
			if err := pg.SetSetting(authKeyVersionKey, version); err != nil {
				t.Fatal(err)
			}
			refresh, err := issueRefreshToken(pg, 0)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "version-write-failure" {
				_, err := pg.Exec(`CREATE FUNCTION reject_auth_version() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.key='auth.key_version' THEN RAISE EXCEPTION 'synthetic version write failure'; END IF; RETURN NEW; END; $$;
CREATE TRIGGER reject_auth_version BEFORE INSERT OR UPDATE ON settings FOR EACH ROW EXECUTE FUNCTION reject_auth_version()`)
				if err != nil {
					t.Fatal(err)
				}
			}
			changed, err := pg.ChangeAuthPassword("synthetic-original-hash", "synthetic-new-hash")
			if err == nil || changed {
				t.Fatal("version failure did not abort password change")
			}
			got, _, err := pg.GetSetting(authPassKey)
			if err != nil || got != "synthetic-original-hash" {
				t.Fatal("password changed despite failed revocation")
			}
			got, _, err = pg.GetSetting(authKeyVersionKey)
			if err != nil || got != version {
				t.Fatal("failed transaction changed key version")
			}
			if _, ok, err := pg.GetSetting(refreshSettingKey(hashRefreshToken(refresh))); err != nil || !ok {
				t.Fatal("failed transaction removed refresh credentials")
			}
		})
	}
}

func TestSecurityPGConcurrentPasswordChangeHasOneWinner(t *testing.T) {
	s, _ := authSecurityPG(t)
	if err := s.m.pg.SetSetting(authPassKey, "synthetic-original-hash"); err != nil {
		t.Fatal(err)
	}
	const attempts = 8
	start := make(chan struct{})
	results := make(chan bool, attempts)
	errs := make(chan error, attempts)
	var ready sync.WaitGroup
	ready.Add(attempts)
	for i := range attempts {
		go func(i int) {
			ready.Done()
			<-start
			changed, err := s.m.pg.ChangeAuthPassword("synthetic-original-hash", fmt.Sprintf("synthetic-new-hash-%d", i))
			results <- changed
			errs <- err
		}(i)
	}
	ready.Wait()
	close(start)
	winners := 0
	for range attempts {
		if <-results {
			winners++
		}
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent old-password changes had %d winners", winners)
	}
	version, _, err := s.m.pg.GetSetting(authKeyVersionKey)
	if err != nil || version != "1" {
		t.Fatalf("version increment was not atomic: %q %v", version, err)
	}
}
