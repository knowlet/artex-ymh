package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSecurityProveGoalFailsClosedWithoutAssetStore(t *testing.T) {
	d, store, goals := plannerProgressStore(t, 1)
	node, err := store.AddNode(db.KindFinding, map[string]any{}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := store.AddStandaloneFinding(0, node, "test", "test", db.SeverityHigh, "summary", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteFinding(finding) })
	toolset := NewToolSet(store, "planner") // Deliberately no AssetStore.
	input := json.RawMessage(fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d}`, goals[0], node))
	result, err := toolset.proveGoal().Call(t.Context(), input, nil)
	if err != nil || !result.IsError || toolset.GoalMet {
		t.Fatalf("pending finding accepted without AssetStore: %+v %v", result, err)
	}
	if _, err := d.SetFindingStatus(finding, db.FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err = toolset.proveGoal().Call(ctx, input, nil)
	if err != nil || !result.IsError || toolset.GoalMet {
		t.Fatalf("cancelled persistence reported success: %+v %v", result, err)
	}
	goal, err := store.GetNode(goals[0])
	if err != nil || goal.State != "open" {
		t.Fatalf("failed call mutated goal: %+v %v", goal, err)
	}
	result, err = toolset.proveGoal().Call(t.Context(), input, nil)
	if err != nil || result.IsError || !toolset.GoalMet {
		t.Fatalf("confirmed proof did not complete: %+v %v", result, err)
	}
}
