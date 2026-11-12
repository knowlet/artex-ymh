package server

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/report"
)

func TestResolveFindingTrafficNilTraffic(t *testing.T) {
	s := &Server{}
	raw := json.RawMessage(`{"steps":[{"request":"GET / HTTP/1.1\n\n","response":""}]}`)
	out := s.resolveFindingTraffic(1, raw)
	if string(out) != string(raw) {
		t.Fatalf("expected unchanged repro")
	}
}

func TestReproductionForFindingParse(t *testing.T) {
	s := &Server{}
	raw := json.RawMessage(`{
		"entry_point":"GET /",
		"steps":[{"request":"GET / HTTP/1.1\n\n","expected":"200"}]
	}`)
	v := s.reproductionForFinding(0, raw, nil)
	rp, ok := v.(report.Reproduction)
	if !ok {
		t.Fatalf("want Reproduction, got %T", v)
	}
	if rp.EntryPoint != "GET /" || len(rp.Steps) != 1 {
		t.Fatalf("unexpected %+v", rp)
	}
}
