package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

func validExploration() *intentExploration {
	return &intentExploration{
		Question:       "Which observation would distinguish a transport failure from an application response?",
		Method:         "Select a configured diagnostic capability within the task scope.",
		ExpectedSignal: "An application response or a transport-level failure with evidence.",
		StopCondition:  "Stop after one discriminating observation or the existing task budget.",
	}
}

func TestIntentExplorationPersistsAndReachesWorker(t *testing.T) {
	_, ts, goals := plannerProgressStore(t, 1)
	prior, err := ts.AddIntent(map[string]any{"summary": "prior fixture observation"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.SetNodeState(prior, "blocked"); err != nil {
		t.Fatal(err)
	}
	plan := validExploration()
	plan.PriorIntentIDs = []int64{prior}
	plan.Change = "Use a different evidence source to answer the previously untested question."
	input, _ := json.Marshal(map[string]any{"summary": "Distinguish the cause with a new observation", "exploration": plan})
	tools := NewToolSet(ts, "planner")
	result, err := tools.addIntent().Call(t.Context(), input, nil)
	if err != nil || result.IsError {
		t.Fatalf("intent submission failed: %+v %v", result, err)
	}
	var id int64
	if _, err := fmt.Sscanf(result.Flatten(), "intent created: %d", &id); err != nil {
		t.Fatal(err)
	}
	node, err := ts.GetNode(id)
	if err != nil || node == nil {
		t.Fatalf("missing persisted intent: %v", err)
	}
	var payload struct {
		Exploration *intentExploration `json:"exploration"`
	}
	if err := json.Unmarshal(node.Payload, &payload); err != nil || payload.Exploration == nil {
		t.Fatalf("experiment was discarded: %s err=%v", node.Payload, err)
	}
	got, _ := json.Marshal(payload.Exploration)
	want, _ := json.Marshal(plan)
	if string(got) != string(want) {
		t.Fatalf("persisted plan differs: %s", got)
	}
	workerInput := renderIntentTask(node)
	for _, value := range []string{plan.Question, plan.ExpectedSignal, plan.StopCondition, plan.Change, "不是强制工具顺序"} {
		if !strings.Contains(workerInput, value) {
			t.Fatalf("worker lost experiment context %q", value)
		}
	}
	compact := compactIntents([]*db.Node{node}, nil, nil)
	if compact[0]["exploration"] == nil {
		t.Fatal("future planner overview lost the experiment rationale")
	}
	priorNode, _ := ts.GetNode(prior)
	goal, _ := ts.GetNode(goals[0])
	facts, _ := ts.ListByKind(db.KindFact, 100)
	if priorNode.State != "blocked" || goal.State != "open" || len(facts) != 0 {
		t.Fatalf("experiment planning changed prior state or fabricated proof: prior=%s goal=%s facts=%d", priorNode.State, goal.State, len(facts))
	}
}

func TestIntentExplorationRejectsInvalidReferencesWithoutWrites(t *testing.T) {
	d, ts, _ := plannerProgressStore(t, 1)
	terminal, _ := ts.AddIntent(map[string]any{"summary": "terminal fixture"}, 5, nil, "planner")
	if err := ts.SetNodeState(terminal, "done"); err != nil {
		t.Fatal(err)
	}
	active, _ := ts.AddIntent(map[string]any{"summary": "active fixture"}, 5, nil, "planner")
	wrongKind, err := ts.AddGoal(map[string]any{"text": "not an intent"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreateExploration(t.Name()+"-other", "unrelated task")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec("DELETE FROM explorations WHERE id=$1", other) })
	foreign, _ := d.Exploration(other).AddIntent(map[string]any{"summary": "foreign fixture"}, 5, nil, "planner")
	if err := d.Exploration(other).SetNodeState(foreign, "done"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*intentExploration)
	}{
		{"missing question", func(p *intentExploration) { p.Question = " " }},
		{"missing expected signal", func(p *intentExploration) { p.ExpectedSignal = "" }},
		{"missing stop condition", func(p *intentExploration) { p.StopCondition = "" }},
		{"missing difference", func(p *intentExploration) { p.PriorIntentIDs = []int64{terminal} }},
		{"active predecessor", func(p *intentExploration) { p.PriorIntentIDs = []int64{active}; p.Change = "changed" }},
		{"foreign predecessor", func(p *intentExploration) { p.PriorIntentIDs = []int64{foreign}; p.Change = "changed" }},
		{"wrong node kind", func(p *intentExploration) { p.PriorIntentIDs = []int64{wrongKind}; p.Change = "changed" }},
		{"nonpositive predecessor", func(p *intentExploration) { p.PriorIntentIDs = []int64{0}; p.Change = "changed" }},
		{"duplicate predecessor", func(p *intentExploration) { p.PriorIntentIDs = []int64{terminal, terminal}; p.Change = "changed" }},
		{"too many predecessors", func(p *intentExploration) { p.PriorIntentIDs = []int64{1, 2, 3, 4, 5}; p.Change = "changed" }},
		{"unbounded field", func(p *intentExploration) { p.Question = strings.Repeat("測", explorationFieldRunes+1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := validExploration()
			test.edit(plan)
			before, _ := ts.ListByKind(db.KindIntent, 100)
			input, _ := json.Marshal(map[string]any{"summary": "must not be created", "exploration": plan})
			result, err := NewToolSet(ts, "planner").addIntent().Call(t.Context(), input, nil)
			after, _ := ts.ListByKind(db.KindIntent, 100)
			if err != nil || !result.IsError || len(before) != len(after) {
				t.Fatalf("invalid experiment wrote an intent: result=%+v err=%v counts=%d/%d", result, err, len(before), len(after))
			}
		})
	}
	// A malformed typed field must not be silently discarded into a legacy intent.
	result, err := NewToolSet(ts, "planner").addIntent().Call(t.Context(), json.RawMessage(`{"summary":"invalid","exploration":{"prior_intent_ids":"wrong type"}}`), nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "Invalid add_intent input") {
		t.Fatalf("malformed experiment was silently accepted: %+v %v", result, err)
	}
	// Legacy submissions remain valid; no experiment field is mandatory.
	result, err = NewToolSet(ts, "planner").addIntent().Call(t.Context(), json.RawMessage(`{"summary":"legacy direction"}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("legacy submission changed: %+v %v", result, err)
	}
}

func TestIntentExplorationSchemaPreservesOverrides(t *testing.T) {
	original := map[string]any{
		"type": "object", "required": []any{"summary"},
		"properties": map[string]any{"summary": map[string]any{"type": "string", "description": "custom wording"},
			"priority": map[string]any{"type": "integer", "default": 7}},
	}
	before, _ := json.Marshal(original)
	tool := DecorateTool(NewToolSet(nil, "planner").addIntent(), "custom tool policy", original)
	after, _ := json.Marshal(original)
	if string(before) != string(after) || tool.Description() != "custom tool policy" {
		t.Fatal("runtime optional schema addition overwrote stored edits")
	}
	properties := tool.InputSchema()["properties"].(map[string]any)
	if properties["exploration"] == nil || properties["priority"].(map[string]any)["default"] != float64(7) ||
		properties["summary"].(map[string]any)["description"] != "custom wording" {
		t.Fatalf("missing optional experiment or lost overrides: %+v", properties)
	}
	again := withIntentExplorationSchema(tool.InputSchema())
	one, _ := json.Marshal(tool.InputSchema())
	two, _ := json.Marshal(again)
	if string(one) != string(two) {
		t.Fatal("optional schema addition is not idempotent")
	}
}

func TestIntentExplorationCompactBounds(t *testing.T) {
	plan := validExploration()
	plan.Question, plan.ExpectedSignal, plan.Change = strings.Repeat("測", 1000), strings.Repeat("試", 1000), strings.Repeat("新", 1000)
	plan.PriorIntentIDs = []int64{1, 2, 3, 4, 5, 6}
	payload, _ := json.Marshal(map[string]any{"exploration": plan})
	compact := compactIntentExploration(payload)
	for _, key := range []string{"question", "expected_signal", "change"} {
		text := compact[key].(string)
		if !utf8.ValidString(text) || utf8.RuneCountInString(text) > 161 {
			t.Fatalf("unbounded compact experiment %s: %d", key, len(text))
		}
	}
	if len(compact["prior_intent_ids"].([]int64)) != explorationPriorCap {
		t.Fatal("compact predecessor list is unbounded")
	}
}
