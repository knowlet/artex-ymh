package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginThrottleCannotBeSpoofedByForwardedHeaders(t *testing.T) {
	s := &Server{authkv: newMemKV()}
	for i := 0; i <= authLoginLimit; i++ {
		r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"wrong","password":"synthetic"}`))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i+2))
		r.Header.Set("X-Real-IP", fmt.Sprintf("198.51.100.%d", i+2))
		w := httptest.NewRecorder()
		s.authLogin(w, r)
		want := 401
		if i == authLoginLimit {
			want = 429
			if w.Header().Get("Retry-After") == "" {
				t.Fatal("throttle omitted Retry-After")
			}
		}
		if w.Code != want {
			t.Fatalf("attempt %d: %d, want %d", i, w.Code, want)
		}
	}
}

func TestLoginThrottleDistributedAttemptsAndRecovery(t *testing.T) {
	var l authAttemptLimiter
	now := time.Now()
	for i := 0; i < authGlobalLimit; i++ {
		if retry := l.allow(fmt.Sprint(i), now); retry != 0 {
			t.Fatalf("early account throttle at %d", i)
		}
	}
	if retry := l.allow("new", now); retry <= 0 {
		t.Fatal("rotating source addresses bypassed account limit")
	}
	if retry := l.allow("new", now.Add(authRateWindow)); retry != 0 {
		t.Fatal("throttle did not recover after its window")
	}
	l.ips = make(map[string]authAttemptBucket)
	for i := 0; i < authMaxIPs; i++ {
		l.ips[fmt.Sprint(i)] = authAttemptBucket{start: now, count: authLoginLimit}
	}
	l.global = authAttemptBucket{start: now}
	if retry := l.allow("overflow", now); retry == 0 || len(l.ips) != authMaxIPs {
		t.Fatal("full limiter cleared active history or grew without bound")
	}
	if retry := l.allow("overflow", now.Add(authRateWindow)); retry != 0 || len(l.ips) != 1 {
		t.Fatal("expired limiter entries were not reclaimed")
	}
}
