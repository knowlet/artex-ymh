package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const defaultLLMReadTimeout = 120 * time.Second

func llmTransportTimeout(name string) time.Duration {
	s := strings.TrimSpace(os.Getenv(name))
	if s == "" {
		return defaultLLMReadTimeout
	}
	seconds, err := strconv.ParseInt(s, 10, 64)
	if err != nil || seconds < 0 || seconds > int64((1<<63-1)/time.Second) {
		log.Printf("[llm-call] WARN %s=%q invalid; using %s", name, s, defaultLLMReadTimeout)
		return defaultLLMReadTimeout
	}
	return time.Duration(seconds) * time.Second
}

// ResponseIdleTimeoutError means the server stopped supplying response bytes.
// It is separate from the total call budget and never masquerades as an HTTP
// status returned by the endpoint.
type ResponseIdleTimeoutError struct{ TimeoutDuration time.Duration }

func (e *ResponseIdleTimeoutError) Error() string {
	return fmt.Sprintf("llm response_idle_timeout: no response bytes for %s", e.TimeoutDuration)
}
func (e *ResponseIdleTimeoutError) Timeout() bool   { return true }
func (e *ResponseIdleTimeoutError) Temporary() bool { return true }
func (e *ResponseIdleTimeoutError) Unwrap() error   { return context.DeadlineExceeded }

// idleTimeoutTransport cancels only a stalled read. Time spent processing a
// chunk by the consumer does not consume the idle budget, and a healthy long
// stream may continue up to the independent overall call deadline.
type idleTimeoutTransport struct {
	base    http.RoundTripper
	timeout time.Duration
}

func (t idleTimeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.timeout <= 0 {
		return t.base.RoundTrip(req)
	}
	ctx, cancel := context.WithCancel(req.Context())
	resp, err := t.base.RoundTrip(req.Clone(ctx))
	if err != nil || resp == nil {
		cancel()
		return resp, err
	}
	if resp.Body == nil {
		cancel()
		return resp, nil
	}
	resp.Body = &idleTimeoutBody{ReadCloser: resp.Body, parent: req.Context(), cancel: cancel, timeout: t.timeout}
	return resp, nil
}

type idleTimeoutBody struct {
	io.ReadCloser
	parent  context.Context
	cancel  context.CancelFunc
	timeout time.Duration
}

func (b *idleTimeoutBody) Read(p []byte) (int, error) {
	var expired atomic.Bool
	finished := make(chan struct{})
	timer := time.AfterFunc(b.timeout, func() {
		expired.Store(true)
		b.cancel()
		close(finished)
	})
	n, err := b.ReadCloser.Read(p)
	if !timer.Stop() {
		<-finished
	}
	if expired.Load() && b.parent.Err() == nil {
		return n, &ResponseIdleTimeoutError{TimeoutDuration: b.timeout}
	}
	return n, err
}

func (b *idleTimeoutBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}
