package db

import (
	"encoding/json"
	"testing"
)

func TestReproductionUsable(t *testing.T) {
	if !reproductionUsable(json.RawMessage(`{"steps":[{"request":"GET /"}]}`)) {
		t.Fatal("expected usable with one step")
	}
	if reproductionUsable(json.RawMessage(`{"steps":[]}`)) {
		t.Fatal("empty steps must not be usable")
	}
	if !reproductionUsable(json.RawMessage(`{"entry_point":"POST /login"}`)) {
		t.Fatal("entry point alone should be usable")
	}
}
