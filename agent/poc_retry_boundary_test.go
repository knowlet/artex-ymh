package agent

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestPOCFollowupTerminalEvidenceDoesNotRedispatch(t *testing.T) {
	t.Setenv("ARTEX_PLANNER_POC_FOLLOWUP", "1")
	for _, state := range []string{"blocked", "done", "done_negative", "exhausted", "paused", "stopped"} {
		t.Run(state, func(t *testing.T) {
			store := pocFollowupPGStore(t)
			fact, err := store.AddNode(db.KindFact, map[string]any{"summary": "authenticated session established", "confidence": "observed"}, 0, "confirmed", "fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			tools := NewToolSet(store, "planner")
			item := intentItem{Summary: "verify fixture PoC", ParentIDs: []json.RawMessage{json.RawMessage(strconv.FormatInt(fact, 10))}}
			id, err := tools.addOneIntent(item)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := store.ClaimIntent(id, "fixture"); err != nil || !ok {
				t.Fatalf("claim %v %v", ok, err)
			}
			if state == "blocked" {
				if r, err := store.ScheduleIntentModelRetry(id, 1, 0, time.Time{}); err != nil || !r.Scheduled {
					t.Fatalf("schedule %+v %v", r, err)
				}
			}
			if state == "done_negative" {
				state = "done"
				negative, err := store.AddNode(db.KindFact, map[string]any{"summary": "no vulnerability observed", "confidence": "inferred"}, 0, "confirmed", "fixture", nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Link(id, db.RelYields, negative); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.SetIntentState(id, state); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				overview := tools.graphOverviewData()
				if g := renderPOCFollowupGuidance(overview); g != "" {
					t.Fatalf("terminal evidence requested new work: %s", g)
				}
			}
			if state != "paused" {
				duplicate, err := tools.addOneIntent(item)
				if err != nil || duplicate != id {
					t.Fatalf("planner reset terminal work with new ID: old=%d new=%d err=%v", id, duplicate, err)
				}
			}
			nodes, err := store.ListByKind(db.KindIntent, 100)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("snapshot/admission created work: %d %v", len(nodes), err)
			}
			fresh, err := store.AddNode(db.KindFact, map[string]any{"summary": "new authenticated session observation", "confidence": "observed"}, 0, "confirmed", "fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			next := item
			next.ParentIDs = []json.RawMessage{json.RawMessage(strconv.FormatInt(fresh, 10))}
			newID, err := tools.addOneIntent(next)
			if err != nil || newID == id {
				t.Fatalf("new evidence swallowed: %d %v", newID, err)
			}
			if state == "blocked" || state == "exhausted" || state == "stopped" {
				if ok, err := store.ReopenIntent(id); err != nil || !ok {
					t.Fatalf("explicit rerun %v %v", ok, err)
				}
			}
		})
	}
}

func TestPOCFollowupOldTerminalEvidenceDoesNotRedispatch(t *testing.T) {
	t.Setenv("ARTEX_PLANNER_POC_FOLLOWUP", "1")
	store := pocFollowupPGStore(t)
	fact, err := store.AddNode(db.KindFact, map[string]any{"summary": "authenticated session established", "confidence": "observed"}, 0, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.AddIntentWithParents(map[string]any{"summary": "verify fixture PoC"}, 5, nil, "planner", []int64{fact})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	for i := range 305 {
		if _, err := store.AddIntent(map[string]any{"summary": strconv.Itoa(i)}, 5, nil, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	tools := NewToolSet(store, "planner")
	if g := renderPOCFollowupGuidance(tools.graphOverviewData()); g != "" {
		t.Fatalf("history window reset evidence coverage: %s", g)
	}
}

func TestPOCFollowupCompletedFindingChildNotRedispatched(t *testing.T) {
	t.Setenv("ARTEX_PLANNER_POC_FOLLOWUP", "1")
	fact := &db.Node{ID: 10, Kind: db.KindFact, Payload: []byte(`{"summary":"authenticated session established","confidence":"observed"}`)}
	enumeration := &db.Node{ID: 1, Kind: db.KindIntent, State: "done"}
	child := &db.Node{ID: 2, Kind: db.KindIntent, State: "done"}
	finding := &db.Node{ID: 20, Kind: db.KindFinding}
	snap := buildPOCFollowupSnapshot([]*db.Node{fact}, []*db.Node{finding}, []*db.Node{enumeration, child}, map[int64][]int64{2: {10}}, map[int64][]int64{2: {20}}, map[int64]int64{10: 1}, nil)
	if len(snap.Candidates) != 1 || snap.Candidates[0]["needs_followup"] != false {
		t.Fatalf("completed finding child requested another verification: %+v", snap)
	}
}
