package server

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func advisoryWorkerTestCleanup(t *testing.T, s *Server) {
	t.Helper()
	t.Cleanup(func() { s.advisoryWG.Wait() })
}

func TestApprovalAdvisoryWorkerAutoReview(t *testing.T) {
	p := &advisoryFake{}
	s, h, id, token := advisoryAPIFixture(t, p)
	advisoryWorkerTestCleanup(t, s)
	consent := time.Now().UTC()
	if err := s.m.pg.SaveAdvisoryAutoConfig(db.AdvisoryAutoConfig{
		Enabled: true, ConsentAt: consent, GlobalSlots: 4, MaxRetries: 2, DailyBudget: 20,
	}); err != nil {
		t.Fatal(err)
	}
	s.startApprovalAdvisoryWorker(t.Context())
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		src, err := s.m.pg.ReadApprovalAdvisory(t.Context(), id)
		if err == nil && src.Advisory != nil && src.Advisory.State == "succeeded" && p.calls.Load() >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("auto worker never reviewed: calls=%d", p.calls.Load())
	}
	w := advisoryRequest(h, id, token, "GET", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"succeeded"`) {
		t.Fatal(w.Code, w.Body)
	}
	src, err := s.m.pg.ReadApprovalAdvisory(t.Context(), id)
	if err != nil || src.Status != "pending" || src.Advisory == nil || src.Advisory.Trigger != "auto" {
		t.Fatalf("pending changed or wrong trigger: %+v err=%v", src, err)
	}
}

func TestApprovalAdvisoryWorkerRespectsCancel(t *testing.T) {
	var waited atomic.Bool
	p := &advisoryFake{hook: func(ctx context.Context) {
		waited.Store(true)
		<-time.After(50 * time.Millisecond)
	}}
	s, _, id, _ := advisoryAPIFixture(t, p)
	advisoryWorkerTestCleanup(t, s)
	consent := time.Now().UTC()
	if err := s.m.pg.SaveAdvisoryAutoConfig(db.AdvisoryAutoConfig{Enabled: true, ConsentAt: consent, GlobalSlots: 2, MaxRetries: 1, DailyBudget: 5}); err != nil {
		t.Fatal(err)
	}
	s.startApprovalAdvisoryWorker(t.Context())
	time.Sleep(6 * time.Second)
	if err := s.m.pg.CancelApprovalAdvisoryAuto(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	meta, _ := s.m.pg.ReadAdvisoryAutoMeta(t.Context(), id)
	if meta == nil || !meta.Cancelled {
		t.Fatal("cancel not persisted")
	}
	before := p.calls.Load()
	time.Sleep(6 * time.Second)
	if p.calls.Load() != before {
		t.Fatal("cancelled pending still triggered reviews")
	}
}

func TestApprovalAdvisoryWorkerShutdownWaitsForInFlightReview(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p := &advisoryFake{hook: func(ctx context.Context) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
	}}
	s, _, _, _ := advisoryAPIFixture(t, p)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		workerCancel()
		s.advisoryWG.Wait()
		close(release)
	})
	s.ctx = workerCtx
	if err := s.m.pg.SaveAdvisoryAutoConfig(db.AdvisoryAutoConfig{
		Enabled: true, ConsentAt: time.Now().UTC(), GlobalSlots: 2, MaxRetries: 1, DailyBudget: 5,
	}); err != nil {
		t.Fatal(err)
	}
	s.startApprovalAdvisoryWorker(workerCtx)
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("auto review never started")
	}
	workerCancel()
	done := make(chan struct{})
	go func() {
		s.advisoryWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("advisory worker did not exit after cancel")
	}
	if _, err := s.m.pg.ReadAdvisoryAutoConfig(context.Background()); err != nil {
		t.Fatalf("database must stay usable until test cleanup: %v", err)
	}
}
