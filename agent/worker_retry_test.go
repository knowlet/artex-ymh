package agent

import (
	"os"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func TestWorkerModelRetryVisibleInPlannerOverview(t *testing.T) {
	d, store, _ := plannerProgressStore(t, 1)
	id, err := store.AddIntent(map[string]any{"summary": "pending recovery direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(id, "work#1"); err != nil || !claimed {
		t.Fatalf("claim=%v %v", claimed, err)
	}
	if r, err := store.ScheduleIntentModelRetry(id, 2, time.Minute, time.Time{}); err != nil || !r.Scheduled {
		t.Fatalf("schedule=%+v %v", r, err)
	}
	data := NewToolSet(store, "planner").graphOverviewData()
	open, ok := data["open_intents"].([]map[string]any)
	if !ok || len(open) != 1 || open[0]["model_retry"] == nil {
		t.Fatalf("planner lost pending recovery: %+v", data["open_intents"])
	}
	progress, err := d.Exploration(store.ID()).PlannerProgress(t.Context())
	if err != nil || progress.NeedsWork() {
		t.Fatalf("pending recovery incorrectly triggers stalled planner: %+v %v", progress, err)
	}
}

func TestWorkerModelRetryRequiresCompleteDurableTranscript(t *testing.T) {
	store := transcript.NewStore(t.TempDir())
	w := &Worker{tx: store}
	if err := w.CheckModelRetryTranscript(1, 2, nil); err == nil {
		t.Fatal("a missing transcript must not restart an intent from scratch")
	}
	writer := store.NewWriter(WorkerSessionID(1, 2), "")
	writer.RecordMessage(llm.UserText("run fixture"), llm.Usage{})
	if err := w.CheckModelRetryTranscript(1, 2, nil); err != nil {
		t.Fatalf("pre-tool model failure can resume: %v", err)
	}
	if err := w.CheckModelRetryTranscript(1, 2, []string{"observed-but-not-persisted"}); err == nil {
		t.Fatal("streamed tool result must be persisted before automatic recovery")
	}
	writer.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "call-1", Name: "fixture"}}}, llm.Usage{})
	if err := w.CheckModelRetryTranscript(1, 2, nil); err == nil {
		t.Fatal("dangling tool call must not be discarded by SDK Resume and repeated")
	}
	writer.RecordMessage(llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call-1", "executed once", false)}}, llm.Usage{})
	if err := w.CheckModelRetryTranscript(1, 2, []string{"call-1"}); err != nil {
		t.Fatalf("complete executed tool history should resume: %v", err)
	}
	if err := os.WriteFile(store.MainPath(WorkerSessionID(1, 2)), []byte("corrupt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.CheckModelRetryTranscript(1, 2, nil); err == nil {
		t.Fatal("corrupt transcript must not be ignored")
	}
	if err := (&Worker{}).CheckModelRetryTranscript(1, 2, nil); err == nil {
		t.Fatal("disabled persistence must not allow automatic intent replay")
	}
}

func TestWorkerModelRetryDoesNotTrustReusedHistoricalToolIDs(t *testing.T) {
	store := transcript.NewStore(t.TempDir())
	w := &Worker{tx: store}
	writer := store.NewWriter(WorkerSessionID(1, 2), "")
	writer.RecordMessage(llm.UserText("previous attempt"), llm.Usage{})
	persistTool := func() {
		writer.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "dsml_0", Name: "fixture"}}}, llm.Usage{})
		writer.RecordMessage(llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("dsml_0", "effect happened", false)}}, llm.Usage{})
	}
	persistTool()
	checkpoint, err := w.ModelRetryCheckpoint(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	writer.RecordMessage(llm.UserText("current attempt"), llm.Usage{})
	if err := w.CheckModelRetryTranscriptSince(1, 2, checkpoint, []string{"dsml_0"}); err == nil {
		t.Fatal("historical dsml_0 must not prove a new side effect was persisted")
	}
	persistTool()
	if err := w.CheckModelRetryTranscriptSince(1, 2, checkpoint, []string{"dsml_0", "dsml_0"}); err == nil {
		t.Fatal("one persisted occurrence must not cover two observed executions")
	}
	persistTool()
	if err := w.CheckModelRetryTranscriptSince(1, 2, checkpoint, []string{"dsml_0", "dsml_0"}); err != nil {
		t.Fatalf("two matched new occurrences should recover: %v", err)
	}
	writer.RecordBoundary(llm.BoundaryMeta{Trigger: "auto"})
	persistTool() // the SDK re-records the old kept tail after compaction
	if err := w.CheckModelRetryTranscriptSince(1, 2, checkpoint, []string{"dsml_0", "dsml_0", "dsml_0"}); err == nil {
		t.Fatal("compacted historical copy must not cover an uncommitted third execution")
	}
	checkpoint.LastUUID = "changed"
	if err := w.CheckModelRetryTranscriptSince(1, 2, checkpoint, nil); err == nil {
		t.Fatal("replaced/truncated transcript checkpoint must fail closed")
	}
}

func TestWorkerModelRetryRejectsMarkerOnlyCompaction(t *testing.T) {
	store := transcript.NewStore(t.TempDir())
	w := &Worker{tx: store}
	writer := store.NewWriter(WorkerSessionID(1, 2), "")
	writer.RecordMessage(llm.UserText("fixture"), llm.Usage{})
	checkpoint, err := w.ModelRetryCheckpoint(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	writer.RecordMessage(llm.BoundaryMessage(llm.BoundaryMeta{Trigger: "auto"}), llm.Usage{})
	writer.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "a", Name: "fixture"}}}, llm.Usage{})
	writer.RecordMessage(llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("a", "copied", false)}}, llm.Usage{})
	if err := w.CheckModelRetryTranscriptSince(1, 2, checkpoint, []string{"a"}); err == nil {
		t.Fatal("marker-only compaction accepted copied result")
	}
}
