package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func wrapIntentArguments(t *testing.T, raw json.RawMessage, stringify bool) json.RawMessage {
	t.Helper()
	var value any = raw
	if stringify {
		value = string(raw)
	}
	wrapped, err := json.Marshal(map[string]any{"arguments": value})
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

func TestIntentArgumentsNormalizesKnownEnvelopes(t *testing.T) {
	const input = `{"summary":"fixture direction","asset_ids":[9007199254740993],"parent_ids":[7],"chain_tags":["web","recon"]}`
	for _, stringified := range []bool{true, false} {
		for layers := 0; layers <= maxIntentArgumentWraps; layers++ {
			t.Run(fmt.Sprintf("string_%t_layers_%d", stringified, layers), func(t *testing.T) {
				raw := json.RawMessage(input)
				for i := 0; i < layers; i++ {
					raw = wrapIntentArguments(t, raw, stringified)
				}
				normalized, _, err := normalizeIntentArguments(raw)
				if err != nil || string(normalized) != input {
					t.Fatalf("normalization changed fields or lost ID precision: %s err=%v", normalized, err)
				}
				items, batch, err := parseIntentArguments(raw)
				if err != nil || batch || len(items) != 1 || items[0].Summary != "fixture direction" ||
					len(items[0].AssetIDs) != 1 || string(items[0].AssetIDs[0]) != "9007199254740993" ||
					len(items[0].ParentIDs) != 1 || string(items[0].ParentIDs[0]) != "7" || len(items[0].ChainTags) != 2 {
					t.Fatalf("wrong single input: %+v batch=%t err=%v", items, batch, err)
				}
			})
		}
	}
	batchInput := json.RawMessage(`{"intents":[{"summary":"first","asset_ids":[1]},{"summary":"second","parent_ids":[2]}]}`)
	items, batch, err := parseIntentArguments(wrapIntentArguments(t, wrapIntentArguments(t, batchInput, true), false))
	if err != nil || !batch || len(items) != 2 || items[0].Summary != "first" || items[1].Summary != "second" ||
		len(items[0].AssetIDs) != 1 || len(items[1].ParentIDs) != 1 {
		t.Fatalf("mixed envelopes lost batch fields: %+v batch=%t err=%v", items, batch, err)
	}
}

func TestIntentArgumentsRejectsAmbiguousEnvelopes(t *testing.T) {
	tooDeep := json.RawMessage(`{"summary":"fixture"}`)
	for i := 0; i <= maxIntentArgumentWraps; i++ {
		tooDeep = wrapIntentArguments(t, tooDeep, true)
	}
	for i, raw := range []string{
		`{"arguments":{"summary":"inner"},"summary":"outer"}`,
		`{"arguments":{"summary":"inner"},"asset_ids":[1]}`,
		`{"arguments":{"summary":"inner"},"arguments":{"summary":"other"}}`,
		`{"summary":"first","Summary":"other"}`,
		`{"arguments":{"summary":"inner","SUMMARY":"other"}}`,
		`{"Arguments":{"summary":"inner"},"summary":"outer"}`,
		`{"arguments":{"arguments":{"summary":"inner"},"parent_ids":[1]}}`,
		`{"arguments":"not JSON"}`,
		`{"arguments":"{\"summary\":\"x\"} trailing"}`,
		`{"arguments":"{\"summary\":"}`,
		`{"arguments":null}`,
		`{"arguments":[]}`,
		`{"arguments":7}`,
		`{"summary":"fixture"} {"summary":"other"}`,
		`{"intents":"wrong type"}`,
		`null`, `[]`, `"{\"summary\":\"fixture\"}"`, ``,
		string(tooDeep),
		`{"summary":"` + strings.Repeat("x", maxIntentArgumentBytes) + `"}`,
	} {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			if _, _, err := parseIntentArguments(json.RawMessage(raw)); err == nil {
				t.Fatalf("ambiguous/malformed input accepted: %.150s", raw)
			}
		})
	}
}

func TestIntentArgumentsRejectsBatchSharedFields(t *testing.T) {
	for _, key := range []string{"summary", "asset_ids", "parent_ids", "priority", "chain_tags", "exploration"} {
		t.Run(key, func(t *testing.T) {
			raw := json.RawMessage(fmt.Sprintf(`{"intents":[{"summary":"fixture"}],%q:null}`, key))
			for _, input := range []json.RawMessage{raw, wrapIntentArguments(t, raw, true)} {
				_, _, err := parseIntentArguments(input)
				if err == nil || !strings.Contains(err.Error(), "inside each intents item") {
					t.Fatalf("shared field silently discarded: %s err=%v", key, err)
				}
			}
		})
	}
}

func TestOpenAIWireWrappedIntentArgumentsPreservedForTool(t *testing.T) {
	input := wrapIntentArguments(t, wrapIntentArguments(t, json.RawMessage(`{"summary":"fixture direction"}`), true), true)
	for _, stream := range []bool{true, false} {
		t.Run(fmt.Sprintf("stream_%t", stream), func(t *testing.T) {
			call := map[string]any{"index": 0, "id": "wrapped", "type": "function", "function": map[string]any{"name": "add_intent", "arguments": string(input)}}
			message := map[string]any{"tool_calls": []any{call}}
			var raw string
			if stream {
				body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": message}}})
				raw = "data: " + string(body) + "\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n"
			} else {
				body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": message, "finish_reason": "tool_calls"}}})
				raw = string(body)
			}
			provider, capture, ctx := toolWireFixture(t, raw, stream)
			request := llm.CompletionRequest{
				Messages: []llm.Message{llm.UserText("plan a fixture direction")},
				Tools:    []llm.ToolSchema{{Name: "add_intent", InputSchema: NewToolSet(nil, "planner").addIntent().InputSchema()}},
			}
			var response llm.Message
			if stream {
				acc := llm.NewAccumulator()
				for event, err := range provider.Stream(ctx, request) {
					if err != nil {
						t.Fatal(err)
					}
					acc.Add(event)
				}
				response = acc.Message()
			} else {
				var err error
				response, _, _, err = provider.Complete(ctx, request)
				if err != nil {
					t.Fatal(err)
				}
			}
			calls := response.ToolUses()
			if len(calls) != 1 || calls[0].Name != "add_intent" || string(calls[0].Input) != string(input) {
				t.Fatalf("provider lost structured arguments: %+v", calls)
			}
			items, batch, err := parseIntentArguments(calls[0].Input)
			if err != nil || batch || len(items) != 1 || items[0].Summary != "fixture direction" {
				t.Fatalf("provider call cannot be normalized by add_intent: %+v batch=%t err=%v", items, batch, err)
			}
			if capture.RawResponse() != raw {
				t.Fatal("raw response audit bytes were changed")
			}
		})
	}
}

func TestAddIntentWrappedCallsPersist(t *testing.T) {
	_, ts, _ := plannerProgressStore(t, 1)
	tool := NewToolSet(ts, "planner").addIntent()
	raw := json.RawMessage(`{"summary":"single fixture","chain_tags":["recon"]}`)
	for i := 0; i < 3; i++ {
		raw = wrapIntentArguments(t, raw, true)
	}
	result, err := tool.Call(t.Context(), raw, nil)
	if err != nil || result.IsError || !strings.HasPrefix(result.Flatten(), "intent created:") {
		t.Fatalf("three-layer single call failed: %+v err=%v", result, err)
	}
	raw = wrapIntentArguments(t, json.RawMessage(`{"intents":[{"summary":"batch first"},{"summary":"batch second"}]}`), true)
	result, err = tool.Call(t.Context(), raw, nil)
	var response struct {
		IDs    []int64           `json:"ids"`
		Errors map[string]string `json:"errors"`
	}
	if err != nil || result.IsError || json.Unmarshal([]byte(result.Flatten()), &response) != nil ||
		len(response.IDs) != 2 || response.IDs[0] == 0 || response.IDs[1] == 0 || len(response.Errors) != 0 {
		t.Fatalf("wrapped batch did not commit both items: %+v err=%v", result, err)
	}
	nodes, err := ts.ListByKind(db.KindIntent, 100)
	if err != nil || len(nodes) != 3 {
		t.Fatalf("wrong persisted intent count: %d err=%v", len(nodes), err)
	}
}

func TestAddIntentWrappedCallsPreserveValidation(t *testing.T) {
	_, ts, _ := plannerProgressStore(t, 1)
	prior, err := ts.AddIntent(map[string]any{"summary": "not a fact parent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	tool := NewToolSet(ts, "planner").addIntent()
	for _, input := range []string{
		fmt.Sprintf(`{"summary":"invalid parent","parent_ids":[%d]}`, prior),
		`{"summary":""}`,
		`{"asset_ids":[1],"intents":[{"summary":"outer asset ids must not be lost"}]}`,
		`{"arguments":{"summary":"inner"},"summary":"outer"}`,
	} {
		result, err := tool.Call(t.Context(), wrapIntentArguments(t, json.RawMessage(input), true), nil)
		if err != nil || !result.IsError {
			t.Fatalf("invalid wrapped call was accepted: %+v err=%v", result, err)
		}
		if strings.Contains(input, "parent_ids") && !strings.Contains(result.Flatten(), "不能作为意图锚点") {
			t.Fatalf("intent parent was remapped or silently dropped: %s", result.Flatten())
		}
	}
	nodes, err := ts.ListByKind(db.KindIntent, 100)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("rejected input left orphan intents: %d err=%v", len(nodes), err)
	}
}

func TestPlannerWrappedIntentCommitsWithinRound(t *testing.T) {
	_, ts, _ := plannerProgressStore(t, 1)
	raw := json.RawMessage(`{"summary":"fixture next observation"}`)
	for i := 0; i < 3; i++ {
		raw = wrapIntentArguments(t, raw, true)
	}
	provider := &plannerProgressProvider{step: func(_ context.Context, _ llm.CompletionRequest, turn int) ([]llm.StreamEvent, error) {
		if turn == 1 {
			return plannerCall(turn, "add_intent", string(raw)), nil
		}
		return plannerText(), nil
	}}
	planner := NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 0)
	_, _, err := planner.Plan(t.Context(), ts.ID(), nil, ts, "fixture", nil, nil)
	if err != nil || len(provider.requests) != 2 {
		t.Fatalf("wrapped call required another planner round: requests=%d err=%v", len(provider.requests), err)
	}
	nodes, err := ts.ListByKind(db.KindIntent, 100)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("planner did not commit exactly one intent: %d err=%v", len(nodes), err)
	}
}
