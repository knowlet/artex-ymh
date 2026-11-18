package server

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestApprovalAdvisoryWorkerAutoReview(t *testing.T) {
	p := &advisoryFake{}
	s, h, id, token := advisoryAPIFixture(t, p)
	consent := time.Now().UTC()
	if err := s.m.pg.SaveAdvisoryAutoConfig(db.AdvisoryAutoConfig{
		Enabled: true, ConsentAt: consent, GlobalSlots: 4, MaxRetries: 2, DailyBudget: 20,
	}); err != nil {
		t.Fatal(err)
	}
	s.startApprovalAdvisoryWorker(t.Context())
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if p.calls.Load() >= 1 {
			break
		}
		time.Sleep(300 * time.Millisecond)
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
