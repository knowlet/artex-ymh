package server

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	authLoginLimit  = 10
	authGlobalLimit = 100 // the installation has one admin account
	authMaxIPs      = 4096
	authRateWindow  = time.Minute
)

type authAttemptBucket struct {
	start time.Time
	count int
}

// Fixed windows bound both bcrypt work and map size. Do not clear active buckets
// when the map fills: that would turn new source addresses into a bypass.
type authAttemptLimiter struct {
	mu     sync.Mutex
	global authAttemptBucket
	ips    map[string]authAttemptBucket
}

func (l *authAttemptLimiter) allow(ip string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.global.start.Add(authRateWindow)) {
		l.global = authAttemptBucket{start: now}
	}
	if l.global.count >= authGlobalLimit {
		return l.global.start.Add(authRateWindow).Sub(now)
	}
	if l.ips == nil {
		l.ips = make(map[string]authAttemptBucket)
	}
	b, exists := l.ips[ip]
	if !exists && len(l.ips) >= authMaxIPs {
		for key, bucket := range l.ips {
			if !now.Before(bucket.start.Add(authRateWindow)) {
				delete(l.ips, key)
			}
		}
		if len(l.ips) >= authMaxIPs {
			return authRateWindow
		}
	}
	if !now.Before(b.start.Add(authRateWindow)) {
		b = authAttemptBucket{start: now}
	}
	if b.count >= authLoginLimit {
		return b.start.Add(authRateWindow).Sub(now)
	}
	b.count++
	l.ips[ip] = b
	l.global.count++
	return 0
}

func (s *Server) allowLoginAttempt(w http.ResponseWriter, r *http.Request) bool {
	// Forwarded headers are client-controlled unless a deployment explicitly
	// establishes a trusted proxy boundary. Use the actual TCP peer here.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || ip == "" {
		ip = r.RemoteAddr
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	if retry := s.loginLimiter.allow(ip, time.Now()); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int((retry+time.Second-1)/time.Second)))
		w.Header().Set("Connection", "close")
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
		writeErr(w, http.StatusTooManyRequests, "登录尝试过于频繁，请稍后重试")
		return false
	}
	return true
}
