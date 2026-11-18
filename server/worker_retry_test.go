package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type workerRecoveryProvider struct {
	step     func(llm.CompletionRequest, int) (llm.Message, string, error)
	requests []llm.CompletionRequest
}

func (p *workerRecoveryProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	msg, stop, err := p.step(req, len(p.requests))
	return msg, stop, llm.Usage{}, err
}

func (p *workerRecoveryProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("fixture expects non-streaming"))
	}
}

func workerRecoveryFixture(t *testing.T) (*Manager, *Task, int64) {
	t.Helper()
	if _, _, err := db.DSN(); err != nil {
		t.Skipf("no disposable PostgreSQL configured: %v", err)
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	pol := m.pg.LLMRetryPolicy()
	t.Cleanup(func() { _ = m.pg.SetLLMRetryPolicy(pol) })
	if err := m.pg.SetLLMRetryPolicy(db.LLMRetryPolicy{}); err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTask(t.Name(), "fixture goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	id, err := task.Store.AddIntent(map[string]any{"summary": "record one fixture fact and finish"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	return m, task, id
}

func newRecoveryWorker(t *testing.T, m *Manager, p llm.Provider) *agent.Worker {
	t.Helper()
	w := agent.NewWorker(p, "fixture", m.dir, transcript.NewStore(filepath.Join(m.dir, "transcripts")), 100000, 5)
	w.SetNonStreaming(func() bool { return true })
	return w
}

func TestWorkerModelRecoveryResumesWithoutRepeatingCommittedTools(t *testing.T) {
	m, task, id := workerRecoveryFixture(t)
	p := &workerRecoveryProvider{step: func(req llm.CompletionRequest, turn int) (llm.Message, string, error) {
		switch turn {
		case 1:
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "committed-fixture", Name: "record_fact",
				Input: []byte(fmt.Sprintf(`{"intent_id":%d,"summary":"fixture service returned its version","evidence":"fixture response v1","confidence":"observed"}`, id))}}}, "tool_use", nil
		case 2:
			return llm.Message{}, "", errors.New("openai: status 504: gateway timeout")
		default:
			found := false
			for _, msg := range req.Messages {
				for _, b := range msg.Content {
					found = found || b.Type == llm.BlockToolResult && b.ToolUseID == "committed-fixture"
				}
			}
			if !found {
				t.Error("retry request lost the committed tool result")
			}
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("Fixture fact already recorded; finished.")}}, "end_turn", nil
		}
	}}
	w := newRecoveryWorker(t, m, p)
	e := NewEngine(m)
	if !e.runWorkerStep(t.Context(), task, "work#1", w) {
		t.Fatal("fixture intent not claimed")
	}
	node, err := task.Store.GetNode(id)
	if err != nil || node.State != "open" || node.ModelRetryCount != 1 || node.ModelRetryAt == nil {
		t.Fatalf("transient error must defer: %+v %v", node, err)
	}
	if len(p.requests) != 2 {
		t.Fatalf("retry must release the worker, provider calls=%d", len(p.requests))
	}
	if got := e.ActiveLLMCalls(task.ID); got != 0 {
		t.Fatalf("cooling work retained active LLM slot: %d", got)
	}
	// Lose all engine memory, then simulate the durable due time without sleeping.
	e = NewEngine(m)
	if e.runWorkerStep(t.Context(), task, "work#2", w) {
		t.Fatal("restart claimed a cooling intent")
	}
	if _, err := m.pg.Exec(`UPDATE exploration_nodes SET model_retry_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if !e.runWorkerStep(t.Context(), task, "work#2", w) {
		t.Fatal("due retry was not claimed")
	}
	node, err = task.Store.GetNode(id)
	if err != nil || node.State != "done" || node.ModelRetryCount != 1 || node.ModelRetryAt != nil {
		t.Fatalf("recovered intent=%+v %v", node, err)
	}
	var facts int
	if err := m.pg.QueryRow(`SELECT count(*) FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel=$3`, task.ExpID, id, db.RelYields).Scan(&facts); err != nil || facts != 1 {
		t.Fatalf("already committed fact was repeated/lost: %d %v", facts, err)
	}
}

func TestWorkerModelRecoveryBudgetSurvivesEngineRestart(t *testing.T) {
	m, task, id := workerRecoveryFixture(t)
	p := &workerRecoveryProvider{step: func(llm.CompletionRequest, int) (llm.Message, string, error) {
		return llm.Message{}, "", errors.New("openai: status 503: unavailable")
	}}
	w := newRecoveryWorker(t, m, p)
	for attempt := 0; attempt < 3; attempt++ {
		e := NewEngine(m)
		if !e.runWorkerStep(t.Context(), task, "work#1", w) {
			t.Fatalf("attempt %d not claimed", attempt)
		}
		n, err := task.Store.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if attempt < 2 {
			if n.State != "open" || n.ModelRetryCount != attempt+1 {
				t.Fatalf("attempt %d: %+v", attempt, n)
			}
			if _, err := m.pg.Exec(`UPDATE exploration_nodes SET model_retry_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
		} else if n.State != "blocked" || n.ModelRetryCount != 2 {
			t.Fatalf("bounded recovery did not stop: %+v", n)
		}
	}
	if len(p.requests) != 3 {
		t.Fatalf("unexpected retry multiplication: %d", len(p.requests))
	}
}

func TestWorkerModelRecoveryRejectsPermanentFailuresAndUnpersistedEffects(t *testing.T) {
	for _, msg := range []string{"openai: status 401: unauthorized", "litellm.ContextWindowExceededError", "invalid JSON", "insufficient_quota"} {
		if retryableWorkerModelError(harness.ReasonModelError, errors.New(msg)) {
			t.Errorf("non-transient model error was retryable: %s", msg)
		}
	}
	store := transcript.NewStore(t.TempDir())
	writer := store.NewWriter(agent.WorkerSessionID(1, 2), "")
	writer.RecordMessage(llm.UserText("fixture"), llm.Usage{})
	w := agent.NewWorker(nil, "fixture", t.TempDir(), store, 0, 0)
	var trace workerRetryTrace
	trace.record(db.Activity{Kind: "tool_use", ToolUseID: "side-effect"})
	if err := trace.check(w, 1, 2); err == nil || !strings.Contains(err.Error(), "unfinished") {
		t.Fatalf("in-flight side effect must not replay: %v", err)
	}
	trace.record(db.Activity{Kind: "tool_result", ToolUseID: "side-effect"})
	if err := trace.check(w, 1, 2); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("executed but unpersisted result must not replay: %v", err)
	}
}

func TestWorkerModelRecoveryRejectsRolledBackRevision(t *testing.T) {
	m, task, id := workerRecoveryFixture(t)
	p := &workerRecoveryProvider{step: func(llm.CompletionRequest, int) (llm.Message, string, error) {
		return llm.Message{}, "", errors.New("HTTP 504 fixture")
	}}
	w := newRecoveryWorker(t, m, p)
	e := NewEngine(m)
	if !e.runWorkerStep(t.Context(), task, "work#1", w) {
		t.Fatal("first attempt missing")
	}
	n, err := task.Store.GetNode(id)
	if err != nil || n.ModelRetryRevision == "" || n.ModelRetryCount != 1 {
		t.Fatalf("revision not persisted %+v %v", n, err)
	}
	path := filepath.Join(m.dir, "transcripts")
	tx := transcript.NewStore(path)
	// A balanced but older/different nonempty history must not start another model call.
	records := []transcript.Record{{Type: "message", UUID: "older", Message: messagePtr(llm.UserText("older fixture"))}}
	raw, err := json.Marshal(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tx.MainPath(agent.WorkerSessionID(task.ExpID, id)), append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`UPDATE exploration_nodes SET model_retry_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	calls := len(p.requests)
	if !NewEngine(m).runWorkerStep(t.Context(), task, "work#2", w) {
		t.Fatal("due retry not claimed")
	}
	n, err = task.Store.GetNode(id)
	if err != nil || n.State != "blocked" || len(p.requests) != calls {
		t.Fatalf("rollback invoked model or failed open %+v calls=%d ->%d err=%v", n, calls, len(p.requests), err)
	}
}
func messagePtr(m llm.Message) *llm.Message { return &m }

func TestWorkerModelRecoveryPauseAfterProgress(t *testing.T) {
	m, task, id := workerRecoveryFixture(t)
	var e *Engine
	p := &workerRecoveryProvider{step: func(_ llm.CompletionRequest, turn int) (llm.Message, string, error) {
		switch turn {
		case 1:
			return llm.Message{}, "", errors.New("HTTP 504 fixture")
		case 2:
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "progress-after-retry", Name: "record_fact", Input: []byte(fmt.Sprintf(`{"intent_id":%d,"summary":"fixture progress","evidence":"fixture observation","confidence":"observed"}`, id))}}}, "tool_use", nil
		case 3:
			e.Pause(task.ID, agent.AbortPausedByUser)
			return llm.Message{}, "", context.Canceled
		default:
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("fixture finished")}}, "end_turn", nil
		}
	}}
	w := newRecoveryWorker(t, m, p)
	e = NewEngine(m)
	if !e.runWorkerStep(t.Context(), task, "work#1", w) {
		t.Fatal("first attempt missing")
	}
	if _, err := m.pg.Exec(`UPDATE exploration_nodes SET model_retry_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if !e.runWorkerStep(t.Context(), task, "work#2", w) {
		t.Fatal("recovery missing")
	}
	n, err := task.Store.GetNode(id)
	if err != nil || n.State != "open" || n.ModelRetryCount != 1 {
		t.Fatalf("pause state=%+v %v", n, err)
	}
	e = NewEngine(m)
	if !e.runWorkerStep(t.Context(), task, "work#3", w) {
		t.Fatal("ordinary resume missing")
	}
	n, err = task.Store.GetNode(id)
	if err != nil || n.State != "done" || n.ModelRetryCount != 1 || len(p.requests) != 4 {
		t.Fatalf("legitimate progress blocked by stale recovery revision: %+v calls=%d err=%v", n, len(p.requests), err)
	}
}
