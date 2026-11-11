package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type loginResetRaceKV struct {
	*memKV
	when string
	once sync.Once
}

func (k *loginResetRaceKV) reset() {
	k.once.Do(func() {
		_ = k.memKV.SetSetting(authKeyVersionKey, "1")
		_ = k.memKV.SetSetting(authPassKey, "synthetic-new-hash")
	})
}

func (k *loginResetRaceKV) GetSetting(key string) (string, bool, error) {
	v, ok, err := k.memKV.GetSetting(key)
	if key == authPassKey && k.when == "password-read" {
		k.reset()
	}
	return v, ok, err
}

func (k *loginResetRaceKV) SetSetting(key, value string) error {
	if strings.HasPrefix(key, "auth.refresh.") && k.when == "session-write" {
		k.reset()
	}
	return k.memKV.SetSetting(key, value)
}

func TestLoginCannotMintNewVersionSessionFromOldPassword(t *testing.T) {
	for _, when := range []string{"password-read", "session-write"} {
		t.Run(when, func(t *testing.T) {
			kv := &loginResetRaceKV{memKV: newMemKV(), when: when}
			hash, err := bcrypt.GenerateFromPassword([]byte("synthetic-old-password"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			_ = kv.memKV.SetSetting(authPassKey, string(hash))
			s := &Server{jwtKey: testJWTKey, authkv: kv}
			w := httptest.NewRecorder()
			s.authLogin(w, httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"ARTEX","password":"synthetic-old-password"}`)))
			if w.Code == 401 {
				if len(w.Result().Cookies()) != 0 {
					t.Fatal("rejected stale login issued refresh cookie")
				}
				return
			}
			if w.Code != 200 {
				t.Fatalf("unexpected login status %d", w.Code)
			}
			var body struct {
				Token string `json:"token"`
			}
			if json.Unmarshal(w.Body.Bytes(), &body) != nil {
				t.Fatal("invalid login response")
			}
			claims, err := parseAccessToken(body.Token, s.jwtKey)
			if err != nil || claims.Ver != 0 || s.validAccessToken(body.Token) {
				t.Fatal("old password obtained a usable post-reset access token")
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name != refreshCookieName {
					continue
				}
				r := httptest.NewRequest("POST", "/api/auth/refresh", nil)
				r.AddCookie(cookie)
				rw := httptest.NewRecorder()
				s.authRefresh(rw, r)
				if rw.Code != 401 {
					t.Fatal("old password obtained a usable post-reset refresh token")
				}
			}
		})
	}
}
