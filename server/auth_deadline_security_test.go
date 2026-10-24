package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the production decoder on real HTTP/1.1 loopback sockets, without
// a database, credentials, or server-wide timeouts masking its own deadline.
type authLoopback struct {
	server   *httptest.Server
	conn     net.Conn
	reader   *bufio.Reader
	started  chan time.Time
	closed   chan struct{}
	accepted atomic.Uint32
}

func newAuthLoopback(t *testing.T) *authLoopback {
	t.Helper()
	s := &authLoopback{started: make(chan time.Time, 8), closed: make(chan struct{})}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.started <- time.Now()
		var req struct {
			Password string `json:"password"`
		}
		if !decodeAuth(w, r, &req) {
			return
		}
		// Stand in for auth logic after decoding; rejected bodies must never
		// reach it. No session or persistent store is used by this harness.
		s.accepted.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	s.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			close(s.closed)
		}
	}
	s.server.Start()
	t.Cleanup(s.server.Close)
	var err error
	s.conn, err = net.DialTimeout("tcp", s.server.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.conn.Close() })
	s.reader = bufio.NewReader(s.conn)
	return s
}

func (s *authLoopback) send(t *testing.T, request string) {
	t.Helper()
	if err := s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(s.conn, request); err != nil {
		t.Fatal(err)
	}
}

func (s *authLoopback) response(t *testing.T, deadline time.Time, want int) *http.Response {
	t.Helper()
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(s.reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("auth response did not arrive within its read budget: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != want {
		t.Fatalf("auth response status=%d want=%d body=%q err=%v", response.StatusCode, want, body, err)
	}
	if response.Header.Get("Set-Cookie") != "" || strings.Contains(string(body), "synthetic") {
		t.Fatal("decoder response exposed credentials or echoed the synthetic password")
	}
	return response
}

func authSocketRequest(body string) string {
	return fmt.Sprintf("POST /api/auth/login HTTP/1.1\r\nHost: loopback\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

func (s *authLoopback) requireAccepted(t *testing.T, want uint32) {
	t.Helper()
	if got := s.accepted.Load(); got != want {
		t.Fatalf("post-decode auth continuation count=%d want=%d", got, want)
	}
}

func (s *authLoopback) requireClosedAndShutdown(t *testing.T) {
	t.Helper()
	// Keep the client open: client cleanup must not be what unblocks the server.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.server.Config.Shutdown(ctx); err != nil {
		t.Fatalf("incomplete auth body blocked graceful shutdown: %v", err)
	}
	select {
	case <-s.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("server retained the incomplete auth body connection after responding")
	}
}

func TestSecurityAuthReadDeadlineLoopbackTimeout(t *testing.T) {
	t.Parallel()
	for _, framing := range []string{"content_length", "chunked_trickle"} {
		t.Run(framing, func(t *testing.T) {
			t.Parallel()
			s := newAuthLoopback(t)
			if framing == "content_length" {
				s.send(t, "POST /api/auth/login HTTP/1.1\r\nHost: loopback\r\nContent-Length: 64\r\n\r\n{\"password\":\"")
			} else {
				s.send(t, "POST /api/auth/login HTTP/1.1\r\nHost: loopback\r\nTransfer-Encoding: chunked\r\n\r\nd\r\n{\"password\":\"\r\n")
			}
			start := <-s.started
			if framing == "chunked_trickle" {
				// Activity continues near the deadline, but may not extend the
				// total read budget. Never send the terminating zero chunk.
				for range 4 {
					time.Sleep(2 * time.Second)
					s.send(t, "1\r\nx\r\n")
				}
			}
			response := s.response(t, start.Add(15*time.Second), http.StatusBadRequest)
			if elapsed := time.Since(start); elapsed < 9*time.Second {
				t.Fatalf("incomplete request rejected before the 10s read deadline: %v", elapsed)
			}
			t.Logf("timeout response after %v; client still open with unfinished body", time.Since(start))
			if !response.Close {
				t.Fatal("timed-out auth connection remained reusable")
			}
			s.requireAccepted(t, 0)
			s.requireClosedAndShutdown(t)
		})
	}
}

func TestSecurityAuthReadDeadlineLoopbackReuse(t *testing.T) {
	t.Parallel()
	s := newAuthLoopback(t)
	// A slow but complete body within the budget must still work. Reuse this
	// exact socket after both a successful decode and fully read invalid JSON.
	body := `{"password":"synthetic"}`
	s.send(t, fmt.Sprintf("POST /api/auth/login HTTP/1.1\r\nHost: loopback\r\nContent-Length: %d\r\n\r\n%s", len(body), body[:5]))
	start := <-s.started
	time.Sleep(100 * time.Millisecond)
	s.send(t, body[5:])
	s.response(t, time.Now().Add(2*time.Second), http.StatusNoContent)
	s.requireAccepted(t, 1)
	// Go also clears its deadline at EOF and between requests. This tests the
	// observable keep-alive behavior past the old deadline; the writer unit
	// test separately checks decodeAuth's explicit clear contract.
	time.Sleep(time.Until(start.Add(11 * time.Second)))
	for _, body := range []string{`{`, `{"password":"synthetic"}`} {
		s.send(t, authSocketRequest(body))
		want := http.StatusNoContent
		if body == "{" {
			want = http.StatusBadRequest
		}
		if s.response(t, time.Now().Add(2*time.Second), want).Close {
			t.Fatal("fully read auth request disabled keep-alive")
		}
		if want == http.StatusBadRequest {
			s.requireAccepted(t, 1)
		} else {
			s.requireAccepted(t, 2)
		}
	}
}

func TestSecurityAuthReadDeadlineLoopbackOversize(t *testing.T) {
	s := newAuthLoopback(t)
	// Only 4 KiB, well below net/http's automatic drain limit. Withhold one
	// byte so a response alone cannot hide a stuck post-handler body Close.
	s.send(t, fmt.Sprintf("POST /api/auth/login HTTP/1.1\r\nHost: loopback\r\nContent-Length: %d\r\n\r\n%s", maxAuthBodyBytes+2, strings.Repeat("x", maxAuthBodyBytes+1)))
	s.response(t, time.Now().Add(2*time.Second), http.StatusRequestEntityTooLarge)
	s.requireAccepted(t, 0)
	s.requireClosedAndShutdown(t)
}

func TestSecurityAuthReadDeadlineLoopbackReadErrors(t *testing.T) {
	for _, framing := range []string{"truncated_length", "invalid_chunk"} {
		t.Run(framing, func(t *testing.T) {
			s := newAuthLoopback(t)
			if framing == "truncated_length" {
				s.send(t, "POST /api/auth/login HTTP/1.1\r\nHost: loopback\r\nContent-Length: 64\r\n\r\n{\"password\":\"")
				if err := s.conn.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
			} else {
				s.send(t, "POST /api/auth/login HTTP/1.1\r\nHost: loopback\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n")
			}
			if !s.response(t, time.Now().Add(2*time.Second), http.StatusBadRequest).Close {
				t.Fatal("failed body read left connection reusable")
			}
			s.requireAccepted(t, 0)
			s.requireClosedAndShutdown(t)
		})
	}
}
