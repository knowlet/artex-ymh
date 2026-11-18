package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
)

type plannerProgressProvider struct {
	requests []llm.CompletionRequest
	step     func(context.Context, llm.CompletionRequest, int) ([]llm.StreamEvent, error)
}

func (p *plannerProgressProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.requests = append(p.requests, req)
		events, err := p.step(ctx, req, len(p.requests))
		for _, event := range events {
			if !yield(event, nil) {
				return
			}
		}
		if err != nil {
			yield(llm.StreamEvent{}, err)
		}
	}
}

func (p *plannerProgressProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for event, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(event)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func plannerText() []llm.StreamEvent {
	return []llm.StreamEvent{{Type: llm.SETextDelta, Text: "The existing evidence still needs a next step."}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
}

func plannerCall(turn int, name, input string) []llm.StreamEvent {
	return []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: fmt.Sprintf("planner-call-%d", turn), ToolName: name},
		{Type: llm.SEToolInputJSON, Text: input}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
}

func plannerProgressStore(t *testing.T, goals int) (*db.DB, *db.ExplorationStore, []int64) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no disposable PostgreSQL configured: %v", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err) // a configured test DB must work; never turn a broken gate green
	}
	t.Cleanup(func() { _ = d.Close() })
	id, err := d.CreateExploration(t.Name(), "verify authorized test fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, id) })
	ts := d.Exploration(id)
	var ids []int64
	for i := 0; i < goals; i++ {
		id, err := ts.AddGoal(map[string]any{"text": fmt.Sprintf("fixture goal %d", i)}, "human")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return d, ts, ids
}

func progressCheckpoint(t *testing.T, d *db.DB, ts *db.ExplorationStore) int {
	t.Helper()
	var raw []byte
	if err := d.QueryRow(`SELECT planner_progress FROM explorations WHERE id=$1`, ts.ID()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var state struct {
		Stalls int `json:"consecutive_stalls"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	return state.Stalls
}

func progressHints(t *testing.T, ts *db.ExplorationStore, state string) int {
	t.Helper()
	nodes, err := ts.ListByKind(db.KindHint, 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, node := range nodes {
		var payload struct{ Kind string }
		if err := json.Unmarshal(node.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Kind == "planner_stalled" && (state == "" || node.State == state) {
			n++
		}
	}
	return n
}

func TestPlannerProgressRecoveryCreatesIntent(t *testing.T) {
	for _, nonStreaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("non_streaming_%t", nonStreaming), func(t *testing.T) {
			d, ts, _ := plannerProgressStore(t, 1)
			provider := &plannerProgressProvider{step: func(_ context.Context, req llm.CompletionRequest, turn int) ([]llm.StreamEvent, error) {
				if turn == 2 {
					hasCorrection := false
					for _, message := range req.Messages {
						hasCorrection = hasCorrection || strings.Contains(message.Text(), "本轮唯一一次纠正")
					}
					if !hasCorrection {
						t.Error("recovery did not include the corrective instruction")
					}
					return plannerCall(turn, "add_intent", `{"summary":"Validate the next fixture observation"}`), nil
				}
				return plannerText(), nil
			}}
			p := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 0)
			p.SetNonStreaming(func() bool { return nonStreaming })
			var retries int
			met, _, err := p.Plan(t.Context(), ts.ID(), nil, ts, "fixture", nil, func(a db.Activity) {
				if strings.Contains(string(a.Metadata), "planner_progress_retry") {
					retries++
				}
			})
			if err != nil || met || len(provider.requests) != 3 || retries != 1 {
				t.Fatalf("met=%v err=%v provider calls=%d retries=%d", met, err, len(provider.requests), retries)
			}
			intents, err := ts.ListByKind(db.KindIntent, 10)
			if err != nil || len(intents) != 1 || intents[0].State != "open" {
				t.Fatalf("intents=%+v err=%v", intents, err)
			}
			if got := progressCheckpoint(t, d, ts); got != 0 {
				t.Fatalf("successful recovery left %d stalls", got)
			}
		})
	}
}

func TestPlannerProgressFailedCallsEscalateDurably(t *testing.T) {
	d, ts, _ := plannerProgressStore(t, 1)
	for round := 1; round <= 5; round++ {
		provider := &plannerProgressProvider{step: func(_ context.Context, _ llm.CompletionRequest, turn int) ([]llm.StreamEvent, error) {
			// Each session attempts a real tool call. Invalid input must not count
			// as success even though a tool_use event exists in the transcript.
			if turn == 1 || turn == 3 {
				return plannerCall(turn, "add_intent", `{"summary":""}`), nil
			}
			return plannerText(), nil
		}}
		// Rebuild the planner each round as settings reload/restart would do.
		p := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 5)
		_, _, err := p.Plan(t.Context(), ts.ID(), nil, ts, "fixture", nil, nil)
		if !errors.Is(err, ErrPlannerNoProgress) {
			t.Fatalf("round %d: error=%v", round, err)
		}
		if len(provider.requests) != 4 {
			t.Fatalf("round %d made %d calls; correction must run only once", round, len(provider.requests))
		}
		if got := progressCheckpoint(t, d, ts); got != min(round, plannerStallThreshold) {
			t.Fatalf("round %d: durable stalls=%d", round, got)
		}
		wantHints := 0
		if round >= plannerStallThreshold {
			wantHints = 1
		}
		if got := progressHints(t, ts, "active"); got != wantHints {
			t.Fatalf("round %d: active warnings=%d want=%d", round, got, wantHints)
		}
	}
	intents, _ := ts.ListByKind(db.KindIntent, 10)
	if len(intents) != 0 {
		t.Fatal("progress monitor invented work for rejected tool calls")
	}
	// Work can be created and finished between rounds; the persisted checkpoint
	// must still reset the failure episode and consume the old warning.
	id, err := ts.AddIntent(map[string]any{"summary": "external fixture work"}, 1, nil, "human")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.SetNodeState(id, "done"); err != nil {
		t.Fatal(err)
	}
	provider := &plannerProgressProvider{step: func(context.Context, llm.CompletionRequest, int) ([]llm.StreamEvent, error) {
		return plannerText(), nil
	}}
	p := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 0)
	_, _, err = p.Plan(t.Context(), ts.ID(), nil, ts, "fixture", nil, nil)
	if !errors.Is(err, ErrPlannerNoProgress) || progressCheckpoint(t, d, ts) != 1 || progressHints(t, ts, "active") != 0 || progressHints(t, ts, "consumed") != 1 {
		t.Fatalf("between-round progress failed to reset episode: err=%v", err)
	}
}

func TestPlannerProgressCommittedActionsDoNotRetry(t *testing.T) {
	for _, scenario := range []string{"fast_done_intent", "partial_goal_proof", "all_goals_proven", "concurrent_active_intent", "out_of_order_commit", "explicit_goal_met", "explicit_goal_met_during_recovery"} {
		t.Run(scenario, func(t *testing.T) {
			goals := 1
			if scenario == "partial_goal_proof" {
				goals = 2
			}
			d, ts, goalIDs := plannerProgressStore(t, goals)
			evidence, err := ts.AddNode(db.KindFact, map[string]any{"summary": "fixture evidence"}, 0, "confirmed", "worker", nil)
			if err != nil {
				t.Fatal(err)
			}
			explicitCompletion := strings.HasPrefix(scenario, "explicit_goal_met")
			if explicitCompletion {
				before, err := ts.PlannerProgress(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < plannerStallThreshold; i++ {
					if _, err := ts.FinishPlannerProgress(t.Context(), before, true, plannerStallThreshold, 5, "completed"); err != nil {
						t.Fatal(err)
					}
				}
				if progressHints(t, ts, "active") != 1 {
					t.Fatal("fixture did not seed an active stall warning")
				}
			}
			var commitLate func() error
			if scenario == "out_of_order_commit" {
				tx, err := d.Begin()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = tx.Rollback() })
				if _, err := tx.Exec(`INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin)
					VALUES ($1,'intent','{"summary":"committed late with lower ID"}','done','planner')`, ts.ID()); err != nil {
					t.Fatal(err)
				}
				id, err := ts.AddIntent(map[string]any{"summary": "higher ID already completed"}, 1, nil, "human")
				if err != nil {
					t.Fatal(err)
				}
				if err := ts.SetNodeState(id, "done"); err != nil {
					t.Fatal(err)
				}
				commitLate = tx.Commit
			}
			provider := &plannerProgressProvider{step: func(_ context.Context, _ llm.CompletionRequest, turn int) ([]llm.StreamEvent, error) {
				// The standalone Plan assembly retains its actual base tools, as
				// production does after goal_met is explicitly bound by ToolResolve.
				// This exercises the real handler without changing default bindings.
				if scenario == "explicit_goal_met" && turn == 1 || scenario == "explicit_goal_met_during_recovery" && turn == 2 {
					return plannerCall(turn, "goal_met", `{"reason":"Fixture completion verified"}`), nil
				}
				if turn == 1 {
					switch scenario {
					case "partial_goal_proof", "all_goals_proven":
						return plannerCall(turn, "prove_goal", fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d}`, goalIDs[0], evidence)), nil
					case "fast_done_intent":
						return plannerCall(turn, "add_intent", `{"summary":"finish fixture immediately"}`), nil
					case "concurrent_active_intent":
						id, err := ts.AddIntent(map[string]any{"summary": "concurrent fixture"}, 1, nil, "human")
						if err != nil {
							t.Fatal(err)
						}
						if _, err := ts.ClaimIntent(id, "test-worker"); err != nil {
							t.Fatal(err)
						}
					case "out_of_order_commit":
						if err := commitLate(); err != nil {
							t.Fatal(err)
						}
					}
				}
				return plannerText(), nil
			}}
			p := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 5)
			retries := 0
			met, reason, err := p.Plan(t.Context(), ts.ID(), nil, ts, "fixture", nil, func(a db.Activity) {
				if strings.Contains(string(a.Metadata), "planner_progress_retry") {
					retries++
				}
				if scenario == "fast_done_intent" && a.Kind == "tool_result" && a.Tool == "add_intent" && !a.IsError {
					intents, err := ts.ListByKind(db.KindIntent, 10)
					if err != nil || len(intents) != 1 {
						t.Fatalf("read created intent: %v %+v", err, intents)
					}
					if err := ts.SetNodeState(intents[0].ID, "done"); err != nil {
						t.Fatal(err)
					}
				}
			})
			wantCalls := 2
			if scenario == "concurrent_active_intent" || scenario == "out_of_order_commit" {
				wantCalls = 1
			}
			wantRetries := 0
			if scenario == "explicit_goal_met_during_recovery" {
				wantCalls, wantRetries = 3, 1
			}
			if err != nil || len(provider.requests) != wantCalls || retries != wantRetries || met != (scenario == "all_goals_proven" || explicitCompletion) || progressCheckpoint(t, d, ts) != 0 {
				t.Fatalf("err=%v calls=%d met=%v", err, len(provider.requests), met)
			}
			if explicitCompletion {
				intents, err := ts.ListByKind(db.KindIntent, 10)
				open, goalErr := ts.HasOpenGoal()
				if err != nil || goalErr != nil || len(intents) != 0 || !open || reason != "Fixture completion verified" || progressHints(t, ts, "active") != 0 || progressHints(t, ts, "consumed") != 1 {
					t.Fatalf("explicit completion changed its contract or left a warning: intents=%d open=%v reason=%q err=%v goalErr=%v", len(intents), open, reason, err, goalErr)
				}
			}
		})
	}
}

func TestPlannerProgressExclusionsAndProviderErrors(t *testing.T) {
	for _, scenario := range []string{"no_goals", "met_goals", "active_intent", "event_wake", "final", "deadline", "cancelled", "provider_error"} {
		t.Run(scenario, func(t *testing.T) {
			goals := 1
			if scenario == "no_goals" {
				goals = 0
			}
			d, ts, ids := plannerProgressStore(t, goals)
			if scenario == "met_goals" {
				if err := ts.SetNodeState(ids[0], "met"); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "active_intent" {
				if _, err := ts.AddIntent(map[string]any{"summary": "already queued"}, 1, nil, "human"); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "final" {
				ctx = WithTaskClock(ctx, TaskClock{Final: true})
			} else if scenario == "deadline" {
				ctx = WithTaskClock(ctx, TaskClock{DeadlineUnix: time.Now().Add(-time.Second).Unix()})
			}
			providerErr := errors.New("fixture provider rejected tool wire")
			provider := &plannerProgressProvider{step: func(_ context.Context, req llm.CompletionRequest, _ int) ([]llm.StreamEvent, error) {
				if scenario == "final" || scenario == "no_goals" || scenario == "met_goals" || scenario == "deadline" {
					for _, msg := range req.Messages {
						if strings.Contains(msg.Text(), "不得产出 0 意图") || strings.Contains(msg.Text(), "当前仍有未达成的目标且没有") {
							t.Error("ineligible round received a forced dispatch prompt")
						}
					}
				}
				if scenario == "provider_error" {
					return nil, providerErr
				}
				if scenario == "cancelled" {
					cancel()
					return nil, context.Canceled
				}
				return plannerText(), nil
			}}
			p := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 0)
			var triggers []TriggerEvent
			if scenario == "event_wake" {
				triggers = []TriggerEvent{{Kind: "goal", Goals: []string{"fixture"}}}
			}
			retries := 0
			_, _, err := p.Plan(ctx, ts.ID(), nil, ts, "fixture", triggers, func(a db.Activity) {
				if strings.Contains(string(a.Metadata), "planner_progress_retry") {
					retries++
				}
			})
			if retries != 0 || len(provider.requests) != 1 {
				t.Fatalf("ineligible round retried: provider calls=%d corrections=%d", len(provider.requests), retries)
			}
			wantStalls := 0
			if scenario == "provider_error" {
				wantStalls = 1
				if !errors.Is(err, providerErr) || !errors.Is(err, ErrPlannerNoProgress) {
					t.Fatalf("provider error lost: %v", err)
				}
			} else if scenario == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if progressCheckpoint(t, d, ts) != wantStalls || progressHints(t, ts, "") != 0 {
				t.Fatal("ineligible round altered stall counter or warning nodes")
			}
		})
	}
}

func TestPlannerProgressRecoveryBudget(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		name      string
		maxTurns  int
		clock     TaskClock
		turns     int
		duration  time.Duration
		permitted bool
	}{
		{"unlimited_original", 0, TaskClock{}, 3, time.Minute, true},
		{"smaller_original", 1, TaskClock{}, 1, time.Minute, true},
		{"task_remaining", 20, TaskClock{DeadlineUnix: 1012}, 3, 12 * time.Second, true},
		{"expired", 0, TaskClock{DeadlineUnix: 999}, 0, 0, false},
		{"final", 0, TaskClock{Final: true}, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			turns, duration, permitted := recoveryBudget(tc.maxTurns, tc.clock, now)
			if turns != tc.turns || duration != tc.duration || permitted != tc.permitted {
				t.Fatalf("got (%d,%v,%t), want (%d,%v,%t)", turns, duration, permitted, tc.turns, tc.duration, tc.permitted)
			}
		})
	}
}

func TestPlannerProgressCorrectionTurnLimit(t *testing.T) {
	for _, maxTurns := range []int{0, 1} {
		t.Run(fmt.Sprintf("max_turns_%d", maxTurns), func(t *testing.T) {
			d, ts, _ := plannerProgressStore(t, 1)
			provider := &plannerProgressProvider{step: func(_ context.Context, _ llm.CompletionRequest, turn int) ([]llm.StreamEvent, error) {
				if turn == 1 {
					return plannerText(), nil
				}
				return plannerCall(turn, "list_goals", `{}`), nil
			}}
			p := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, maxTurns)
			_, _, err := p.Plan(t.Context(), ts.ID(), nil, ts, "fixture", nil, nil)
			wantCalls := 1 + plannerRecoveryTurns
			if maxTurns > 0 {
				wantCalls = 1 + maxTurns
			}
			if !errors.Is(err, ErrPlannerNoProgress) || len(provider.requests) != wantCalls || progressCheckpoint(t, d, ts) != 1 {
				t.Fatalf("unbounded correction or wrong outcome: calls=%d want=%d err=%v", len(provider.requests), wantCalls, err)
			}
		})
	}
}

func TestPlannerProgressNoopProofAndCancelledIntent(t *testing.T) {
	for _, scenario := range []string{"invalid_proof", "already_met_proof", "cancelled_intent", "deleted_intent"} {
		t.Run(scenario, func(t *testing.T) {
			d, ts, ids := plannerProgressStore(t, 2)
			evidence, err := ts.AddNode(db.KindFact, map[string]any{"summary": "fixture evidence"}, 0, "confirmed", "worker", nil)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "already_met_proof" {
				if err := ts.SetNodeState(ids[0], "met"); err != nil {
					t.Fatal(err)
				}
			}
			provider := &plannerProgressProvider{step: func(_ context.Context, _ llm.CompletionRequest, turn int) ([]llm.StreamEvent, error) {
				if turn == 1 {
					switch scenario {
					case "invalid_proof":
						return plannerCall(turn, "prove_goal", fmt.Sprintf(`{"goal_id":%d,"evidence_id":0}`, ids[0])), nil
					case "already_met_proof":
						return plannerCall(turn, "prove_goal", fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d}`, ids[0], evidence)), nil
					default:
						return plannerCall(turn, "add_intent", `{"summary":"fixture cancelled before doing work"}`), nil
					}
				}
				if turn == 2 && scenario == "cancelled_intent" {
					intents, err := ts.ListByKind(db.KindIntent, 10)
					if err != nil || len(intents) != 1 {
						t.Fatalf("read created intent: %v %+v", err, intents)
					}
					return plannerCall(turn, "cancel_intent", fmt.Sprintf(`{"intent_id":%d,"reason":"fixture cancellation"}`, intents[0].ID)), nil
				}
				return plannerText(), nil
			}}
			p := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 5)
			retries := 0
			_, _, err = p.Plan(t.Context(), ts.ID(), nil, ts, "fixture", nil, func(a db.Activity) {
				if strings.Contains(string(a.Metadata), "planner_progress_retry") {
					retries++
				}
				if scenario == "deleted_intent" && a.Kind == "tool_result" && a.Tool == "add_intent" && !a.IsError {
					intents, err := ts.ListByKind(db.KindIntent, 10)
					if err != nil || len(intents) != 1 {
						t.Fatalf("read created intent: %v %+v", err, intents)
					}
					if err := ts.SetNodeState(intents[0].ID, "deleted"); err != nil {
						t.Fatal(err)
					}
				}
			})
			if !errors.Is(err, ErrPlannerNoProgress) || retries != 1 || progressCheckpoint(t, d, ts) != 1 {
				t.Fatalf("non-progressful tool call counted as success: err=%v retries=%d", err, retries)
			}
		})
	}
}

func TestPlannerBeforeProgressReadFailureBestEffort(t *testing.T) {
	d, ts, _ := plannerProgressStore(t, 1)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	before, ok := plannerBeforeProgress(t.Context(), ts, TaskClock{})
	if ok || before.NeedsWork() || len(before.IntentIDs) > 0 {
		t.Fatalf("failed before read must yield zero snapshot and beforeOK=false: ok=%v before=%+v", ok, before)
	}
}

func TestPlannerProgressUnreliableBeforeSkipsStallDetection(t *testing.T) {
	d, ts, _ := plannerProgressStore(t, 1)
	provider := &plannerProgressProvider{step: func(context.Context, llm.CompletionRequest, int) ([]llm.StreamEvent, error) {
		return plannerText(), nil
	}}
	p := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 5)
	retries := 0
	err := p.runWithProgressCheck(t.Context(), agentcore.Options{Provider: provider, MaxTurns: 5},
		"heartbeat fixture", ts, db.PlannerProgress{}, false, true,
		func() map[string]any { return nil }, func() bool { return false },
		func(a db.Activity) {
			if strings.Contains(string(a.Metadata), "planner_progress_retry") {
				retries++
			}
		})
	if errors.Is(err, ErrPlannerNoProgress) || retries != 0 {
		t.Fatalf("unreliable before must not trigger correction or stall escalation: err=%v retries=%d", err, retries)
	}
	if len(provider.requests) != 1 {
		t.Fatalf("provider calls=%d want 1", len(provider.requests))
	}
	if progressCheckpoint(t, d, ts) != 0 {
		t.Fatal("stall counter must remain zero when before snapshot was unavailable")
	}
}
