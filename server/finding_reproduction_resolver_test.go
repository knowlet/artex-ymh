package server

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/report"
)

func TestResolveFindingTrafficNoTaskStoreAbstains(t *testing.T) {
	s := &Server{}
	raw := json.RawMessage(`{"steps":[{"request":"GET /x HTTP/1.1\nHost: h\n\n","response":""}]}`)
	out := s.resolveFindingTraffic(0, raw)
	if string(out) != string(raw) {
		t.Fatalf("expected unchanged repro without task")
	}
}

func TestReproductionForFindingPartialResolve(t *testing.T) {
	s := &Server{}
	raw := json.RawMessage(`{"steps":[
		{"request":"GET /a HTTP/1.1\nHost: h\n\n","exchange_id":"keep"},
		{"request":"GET /b HTTP/1.1\nHost: h\n\n"}
	]}`)
	taskID := int64(1)
	v := s.reproductionForFinding(0, raw, &taskID)
	rp, ok := v.(report.Reproduction)
	if !ok {
		t.Fatalf("want Reproduction, got %T", v)
	}
	if rp.Steps[0].ExchangeID != "keep" {
		t.Fatalf("step0 exchange_id should be preserved, got %q", rp.Steps[0].ExchangeID)
	}
}
