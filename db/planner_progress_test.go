package db

import "testing"

// A saturated count of one is not evidence of a new stall episode. Even when
// escalation is immediate, repeated checks must retain the existing active hint.
func TestPlannerProgressThresholdOneDeduplicatesHints(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	expID, err := d.CreateExploration(t.Name(), "fixture goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	ts := d.Exploration(expID)
	if _, err := ts.AddGoal(map[string]any{"text": "fixture goal"}, "human"); err != nil {
		t.Fatal(err)
	}
	before, err := ts.PlannerProgress(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	assertHints := func(active, consumed int) {
		t.Helper()
		var gotActive, gotConsumed int
		if err := d.QueryRow(`SELECT COUNT(*) FILTER (WHERE state='active'), COUNT(*) FILTER (WHERE state='consumed')
			FROM exploration_nodes WHERE exploration_id=$1 AND kind='hint' AND origin='scheduler'
			AND payload->>'kind'='planner_stalled'`, expID).Scan(&gotActive, &gotConsumed); err != nil {
			t.Fatal(err)
		}
		if gotActive != active || gotConsumed != consumed {
			t.Fatalf("hints active=%d consumed=%d, want active=%d consumed=%d", gotActive, gotConsumed, active, consumed)
		}
	}
	var firstHintID int64
	for round := 0; round < 3; round++ {
		// Recreate the store handle to ensure deduplication comes from the database.
		report, err := d.Exploration(expID).FinishPlannerProgress(t.Context(), before, true, 1, 0, "completed")
		if err != nil || report.ConsecutiveStalls != 1 {
			t.Fatalf("round %d: report=%+v err=%v", round, report, err)
		}
		if round == 0 {
			firstHintID = report.HintID
			if firstHintID <= 0 {
				t.Fatal("first stall did not create an immediate escalation")
			}
		} else if report.HintID != 0 {
			t.Fatalf("round %d replaced the existing warning with hint %d", round, report.HintID)
		}
		assertHints(1, 0)
	}
	// Real progress between rounds starts a new episode. The old warning must
	// then be consumed and an immediate threshold-one warning may be created.
	intentID, err := ts.AddIntent(map[string]any{"summary": "fixture work between rounds"}, 1, nil, "human")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.SetNodeState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	before, err = ts.PlannerProgress(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	report, err := ts.FinishPlannerProgress(t.Context(), before, true, 1, 0, "completed")
	if err != nil || report.ConsecutiveStalls != 1 || report.HintID <= 0 || report.HintID == firstHintID {
		t.Fatalf("new episode report=%+v err=%v", report, err)
	}
	assertHints(1, 1)
	report, err = ts.FinishPlannerProgress(t.Context(), before, false, 1, 0, "completed")
	if err != nil || report.ConsecutiveStalls != 0 || report.HintID != 0 {
		t.Fatalf("resolved episode report=%+v err=%v", report, err)
	}
	assertHints(0, 2)
}
