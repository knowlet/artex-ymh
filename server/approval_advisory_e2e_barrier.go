// Advisory Playwright E2E barrier fake (disposable env only).

package server

import (
	"context"
	"iter"
	"net/http"
	"sync"

	"github.com/Autumn-27/norma/llm"
)

// advisoryE2EBarrierFake blocks the model call until ReleaseInference or ctx cancel.
type advisoryE2EBarrierFake struct {
	text string
	mu   sync.Mutex
	block   bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newAdvisoryE2EBarrierFake(text string) *advisoryE2EBarrierFake {
	return &advisoryE2EBarrierFake{
		text:    text,
		block:   true,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (f *advisoryE2EBarrierFake) waitBarrier(ctx context.Context) {
	f.mu.Lock()
	block := f.block
	f.mu.Unlock()
	if !block {
		return
	}
	f.once.Do(func() { close(f.entered) })
	select {
	case <-f.release:
	case <-ctx.Done():
	}
}

func (f *advisoryE2EBarrierFake) setBlock(on bool) {
	f.mu.Lock()
	f.block = on
	f.mu.Unlock()
}

func (f *advisoryE2EBarrierFake) releaseInference() {
	select {
	case <-f.release:
	default:
		close(f.release)
	}
}

func (f *advisoryE2EBarrierFake) inferenceEntered() bool {
	select {
	case <-f.entered:
		return true
	default:
		return false
	}
}

func (f *advisoryE2EBarrierFake) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	f.waitBarrier(ctx)
	if ctx.Err() != nil {
		return llm.Message{}, "", llm.Usage{}, ctx.Err()
	}
	text := f.text
	if text == "" {
		text = advisoryE2EFixtureReply
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}, "end_turn", llm.Usage{}, nil
}

func (f *advisoryE2EBarrierFake) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		msg, reason, _, err := f.Complete(ctx, req)
		if err != nil {
			y(llm.StreamEvent{}, err)
			return
		}
		if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: msg.Text()}, nil) {
			return
		}
		y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: reason}, nil)
		y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

// advisoryE2EControl serves harness-only routes when ARTEX_E2E_SERVE is set.
type advisoryE2EControl struct {
	srv     *Server
	fake    *advisoryE2EBarrierFake
	envPath string
}

func (c *advisoryE2EControl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method + " " + r.URL.Path {
	case "POST /api/e2e/advisory/release-inference":
		c.fake.releaseInference()
		w.WriteHeader(http.StatusNoContent)
	case "GET /api/e2e/advisory/inference-entered":
		if c.fake.inferenceEntered() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
	case "POST /api/e2e/advisory/seed-auto-pending":
		c.fake.setBlock(false)
		id, err := c.srv.AdvisoryE2ESeedAutoPending(r.Context())
		if err != nil {
			writeErr(w, 503, "seed failed")
			return
		}
		if c.envPath != "" {
			_ = AppendAdvisoryE2EAutoPendingID(c.envPath, id)
		}
		writeJSON(w, http.StatusOK, map[string]any{"pending_id": id})
	default:
		http.NotFound(w, r)
	}
}

func wrapAdvisoryE2EHandler(inner http.Handler, ctl *advisoryE2EControl) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/e2e/advisory/release-inference" ||
			r.URL.Path == "/api/e2e/advisory/inference-entered" ||
			r.URL.Path == "/api/e2e/advisory/seed-auto-pending" {
			ctl.ServeHTTP(w, r)
			return
		}
		inner.ServeHTTP(w, r)
	})
}
