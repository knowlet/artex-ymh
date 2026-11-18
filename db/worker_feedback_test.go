package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func workerFeedbackStore(t *testing.T) (*DB, *ExplorationStore) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	id, err := d.CreateExploration(t.Name(), "worker feedback fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, id) })
	return d, d.Exploration(id)
}

func feedbackIntent(t *testing.T, store *ExplorationStore, state string) int64 {
	t.Helper()
	id, err := store.AddIntent(map[string]any{"summary": "fixture observation"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(id, state); err != nil {
		t.Fatal(err)
	}
	return id
}

func feedbackActivity(t *testing.T, store *ExplorationStore, intentID int64, kind, text string, isError bool) int64 {
	t.Helper()
	id, err := store.AppendActivity(Activity{
		NodeID: &intentID, Worker: "worker", Kind: kind, Tool: "Bash", IsError: isError, Summary: text, Detail: text,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestWorkerOutputLatestBeyondInitialPage(t *testing.T) {
	d, store := workerFeedbackStore(t)
	intentID := feedbackIntent(t, store, "done")
	if _, err := d.Exec(`INSERT INTO activity(exploration_id,node_id,worker,kind,tool,summary,detail)
SELECT $1,$2,'worker','tool_result','Bash','old step','old detail' FROM generate_series(1,1100)`, store.ID(), intentID); err != nil {
		t.Fatal(err)
	}
	firstText := feedbackActivity(t, store, intentID, "text", "earlier partial text", false)
	latestText := feedbackActivity(t, store, intentID, "text", "latest partial text", false)
	got, err := store.LatestWorkerOutputWithSources(intentID)
	if err != nil || got == nil || got.ID != latestText || got.ID == firstText || got.Detail != "latest partial text" {
		t.Fatalf("latest text missing after old page: got=%+v err=%v", got, err)
	}
	resultID := feedbackActivity(t, store, intentID, "result", "actual final conclusion", true)
	feedbackActivity(t, store, intentID, "text", "newer text must not replace result", false)
	feedbackActivity(t, store, intentID, "thinking", "private reasoning", false)
	got, err = store.LatestWorkerOutputWithSources(intentID)
	if err != nil || got == nil || got.ID != resultID || got.Detail != "actual final conclusion" || !got.IsError || got.Inherited {
		t.Fatalf("final result lost or private row selected: got=%+v err=%v", got, err)
	}
	newResult := feedbackActivity(t, store, intentID, "result", "later completed continuation", false)
	got, err = store.LatestWorkerOutputWithSources(intentID)
	if err != nil || got == nil || got.ID != newResult {
		t.Fatalf("latest continuation result missing: got=%+v err=%v", got, err)
	}
	other, err := d.CreateExploration("unrelated feedback", "not readable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, other) })
	if got, err := d.Exploration(other).LatestWorkerOutputWithSources(intentID); err != nil || got != nil {
		t.Fatalf("unrelated output leaked: got=%+v err=%v", got, err)
	}
	feedback, err := store.RecentWorkerFeedback(6)
	if err != nil || len(feedback) != 1 || feedback[0].LatestOutput == nil || feedback[0].LatestOutput.StepID != newResult || !feedback[0].EarlierActivityOmitted {
		t.Fatalf("overview feedback lost late conclusion: got=%+v err=%v", feedback, err)
	}
}

func TestWorkerOutputInheritedTerminalBoundary(t *testing.T) {
	d, _ := workerFeedbackStore(t)
	grand, err := d.CreateTask("feedback grandparent", "private grandparent", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	source, err := d.CreateTaskWithOptions("feedback source", "source goal", TaskCreateOptions{SourceTaskIDs: []int64{grand.ID}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.CreateTaskWithOptions("feedback current", "current goal", TaskCreateOptions{SourceTaskIDs: []int64{source.ID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.DeleteTask(current.ID)
		_ = d.DeleteTask(source.ID)
		_ = d.DeleteTask(grand.ID)
	})
	store := d.Exploration(current.ExplorationID)
	sourceStore := d.Exploration(source.ExplorationID)
	intentID := feedbackIntent(t, sourceStore, "done")
	resultID := feedbackActivity(t, sourceStore, intentID, "result", "shared terminal conclusion", false)
	feedbackActivity(t, sourceStore, intentID, "thinking", "private source thinking", false)
	got, err := store.LatestWorkerOutputWithSources(intentID)
	if err != nil || got == nil || got.ID != resultID || !got.Inherited || got.SourceTaskID != source.ID {
		t.Fatalf("direct output attribution: got=%+v err=%v", got, err)
	}
	// Hold the old terminal node just as a tool caller can, then reopen it. The
	// latest-output query itself must enforce the current state, not this snapshot.
	staleNode, err := store.GetNodeWithSources(intentID)
	if err != nil || staleNode == nil || !staleNode.Inherited {
		t.Fatalf("source snapshot missing: node=%+v err=%v", staleNode, err)
	}
	if err := sourceStore.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	feedbackActivity(t, sourceStore, intentID, "text", "private resumed work", false)
	if got, err := store.LatestWorkerOutputWithSources(intentID); err != nil || got != nil {
		t.Fatalf("reopened source output leaked: got=%+v err=%v", got, err)
	}
	if err := sourceStore.SetIntentState(intentID, "exhausted"); err != nil {
		t.Fatal(err)
	}
	got, err = store.LatestWorkerOutputWithSources(intentID)
	if err != nil || got == nil || got.ID != resultID {
		t.Fatalf("terminal result precedence changed: got=%+v err=%v", got, err)
	}
	grandStore := d.Exploration(grand.ExplorationID)
	grandID := feedbackIntent(t, grandStore, "done")
	feedbackActivity(t, grandStore, grandID, "result", "not directly related", false)
	if got, err := store.LatestWorkerOutputWithSources(grandID); err != nil || got != nil {
		t.Fatalf("recursive source leaked: got=%+v err=%v", got, err)
	}
	feedback, err := store.RecentWorkerFeedback(6)
	if err != nil || len(feedback) != 0 {
		t.Fatalf("current feedback inherited source work: got=%+v err=%v", feedback, err)
	}
	if err := d.DeleteTask(source.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := store.LatestWorkerOutputWithSources(intentID); err != nil || got != nil {
		t.Fatalf("deleted source leaked: got=%+v err=%v", got, err)
	}
}

func TestRecentWorkerFeedbackBoundedAndFactual(t *testing.T) {
	d, store := workerFeedbackStore(t)
	var newest int64
	for i := 0; i < workerFeedbackIntentLimit+2; i++ {
		newest = feedbackIntent(t, store, "blocked")
		if _, err := d.Exec(`INSERT INTO activity(exploration_id,node_id,worker,kind,tool,is_error,summary,detail)
SELECT $1,$2,'worker','tool_result','fixture-tool-' || (g % 12),true,'short error',$3
FROM generate_series(1,150) g`, store.ID(), newest, strings.Repeat("錯誤", 500)); err != nil {
			t.Fatal(err)
		}
		feedbackActivity(t, store, newest, "result", strings.Repeat("結論", 500), true)
	}
	lastID := feedbackActivity(t, store, newest, "thinking", "PRIVATE_NOT_IN_FEEDBACK", false)
	for _, excluded := range []string{"open", "running", "stopped", "deleted"} {
		id := feedbackIntent(t, store, excluded)
		feedbackActivity(t, store, id, "result", "EXCLUDED_STATE_"+excluded, false)
	}
	feedback, err := store.RecentWorkerFeedback(1000)
	if err != nil || len(feedback) != workerFeedbackIntentLimit {
		t.Fatalf("feedback window: rows=%d err=%v", len(feedback), err)
	}
	f := feedback[0]
	if f.IntentID != newest || f.LastActivityID != lastID || f.SampledActivityCount != 128 || !f.EarlierActivityOmitted || f.SampledToolResults != 126 || f.SampledToolErrors != 126 {
		t.Fatalf("tail sample or cursor inaccurate: %+v", f)
	}
	if f.LatestOutput == nil || !f.LatestOutput.Truncated || utf8.RuneCountInString(f.LatestOutput.Excerpt) != workerFeedbackOutputRunes {
		t.Fatalf("output excerpt not bounded: %+v", f.LatestOutput)
	}
	if len(f.Tools) != workerFeedbackToolLimit || f.ToolNamesOmitted != 4 || len(f.RecentErrors) != workerFeedbackErrorLimit {
		t.Fatalf("tool/error summaries not bounded: %+v", f)
	}
	for _, failure := range f.RecentErrors {
		if !failure.Truncated || utf8.RuneCountInString(failure.Excerpt) != workerFeedbackErrorRunes || !utf8.ValidString(failure.Excerpt) || failure.StepID <= 0 {
			t.Fatalf("invalid error excerpt: %+v", failure)
		}
	}
	encoded, err := json.Marshal(feedback)
	if err != nil || len(encoded) > 50_000 || !utf8.Valid(encoded) || strings.Contains(string(encoded), "PRIVATE_NOT_IN_FEEDBACK") || strings.Contains(string(encoded), "EXCLUDED_STATE_") {
		t.Fatalf("feedback content/byte bound violated: bytes=%d err=%v", len(encoded), err)
	}
	// Refreshing the same graph is stable; a new terminal observation changes
	// the cursor and evidence reference without manufacturing a new fact.
	again, err := store.RecentWorkerFeedback(6)
	if err != nil || again[0].LastActivityID != f.LastActivityID {
		t.Fatalf("unchanged feedback cursor changed: got=%+v err=%v", again, err)
	}
	newResult := feedbackActivity(t, store, newest, "result", "new bounded conclusion", false)
	again, err = store.RecentWorkerFeedback(6)
	if err != nil || again[0].LastActivityID != newResult || again[0].LatestOutput.StepID != newResult || again[0].LatestOutput.Truncated {
		t.Fatalf("updated conclusion missing: got=%+v err=%v", again, err)
	}
	var facts int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND state<>'origin'`, store.ID()).Scan(&facts); err != nil || facts != 0 {
		t.Fatal(fmt.Sprintf("feedback fabricated facts: count=%d err=%v", facts, err))
	}
	// Display clipping must not merge different tool names with a long common
	// prefix. An intent without a result/text must remain explicitly without one.
	longNames := feedbackIntent(t, store, "done")
	for _, suffix := range []string{"first", "second"} {
		if _, err := store.AppendActivity(Activity{NodeID: &longNames, Kind: "tool_result", Tool: strings.Repeat("tool", 40) + suffix}); err != nil {
			t.Fatal(err)
		}
	}
	again, err = store.RecentWorkerFeedback(1)
	if err != nil || len(again) != 1 || again[0].LatestOutput != nil || len(again[0].Tools) != 2 {
		t.Fatalf("long tool names merged or output invented: got=%+v err=%v", again, err)
	}
	for _, tool := range again[0].Tools {
		if !tool.NameTruncated || tool.Results != 1 || utf8.RuneCountInString(tool.Name) > workerFeedbackToolRunes {
			t.Fatalf("long tool display/count invalid: %+v", tool)
		}
	}
}
