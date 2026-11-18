package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/llmwire"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
)

// These fixtures exercise Config.NewProvider -> capture transport -> llmwire ->
// the real pinned Norma provider/Accumulator. No LLM, database or tool execution.
func toolWireRequest() llm.CompletionRequest {
	return llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("read the fictional trace")},
		Tools: []llm.ToolSchema{{Name: "get_worker_trace", InputSchema: map[string]any{
			"type": "object", "required": []string{"intent_id"}, "properties": map[string]any{"intent_id": map[string]any{"type": "integer"}},
		}}},
	}
}
func toolWireFixture(t *testing.T, raw string, stream bool) (llm.Provider, *llmrec.Capture, context.Context) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/chat/completions" || req["stream"] != stream {
			t.Errorf("path=%s stream=%v", r.URL.Path, req["stream"])
		}
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = io.WriteString(w, raw)
	}))
	t.Cleanup(srv.Close)
	cfg := ConfigFrom("openai", "deepseek-v4-flash", srv.URL, "fixture-key", "")
	cfg.Retry.ConnectAttempts = -1
	cfg.Retry.EmptyAttempts = -1
	prov, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	ctx, capt := llmrec.NewCapture(context.Background())
	return prov, capt, ctx
}

const wireInterleaved = `data: {"choices":[{"index":0,"delta":{"reasoning_content":"fixture reasoning"}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":"}},{"index":1,"id":"b","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":"}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"4}"}},{"index":1,"function":{"arguments":"9}"}}]}}]}

data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":8}}

data: [DONE]

`

func TestOpenAIWireInterleavedArgumentsAndRawCapture(t *testing.T) {
	prov, capt, ctx := toolWireFixture(t, wireInterleaved, true)
	acc := llm.NewAccumulator()
	for ev, err := range prov.Stream(ctx, toolWireRequest()) {
		if err != nil {
			t.Fatal(err)
		}
		acc.Add(ev)
	}
	calls := acc.Message().ToolUses()
	if len(calls) != 2 || calls[0].Name != "get_worker_trace" || string(calls[0].Input) != `{"intent_id":4}` || string(calls[1].Input) != `{"intent_id":9}` {
		t.Fatalf("calls=%+v", calls)
	}
	if acc.StopReason != "tool_use" || acc.Usage.InputTokens != 5 || acc.Usage.OutputTokens != 8 {
		t.Fatalf("stop=%s usage=%+v", acc.StopReason, acc.Usage)
	}
	if capt.RawResponse() != wireInterleaved {
		t.Fatal("raw_response was normalized or truncated")
	}
	if !strings.Contains(capt.RawRequest(), `"model":"deepseek-v4-flash"`) {
		t.Fatal("raw_request lost model")
	}
}
func TestOpenAIWireDelayedToolName(t *testing.T) {
	raw := `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"get_worker_trace","arguments":"{\"intent_id\":4}"}}]}}]}

data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`
	prov, _, ctx := toolWireFixture(t, raw, true)
	acc := llm.NewAccumulator()
	for ev, err := range prov.Stream(ctx, toolWireRequest()) {
		if err != nil {
			t.Fatal(err)
		}
		acc.Add(ev)
	}
	calls := acc.Message().ToolUses()
	if len(calls) != 1 || calls[0].Name != "get_worker_trace" {
		t.Fatalf("calls=%+v", calls)
	}
}
func workerOutputWireRequest() llm.CompletionRequest {
	return llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("read worker outputs")},
		Tools: []llm.ToolSchema{{Name: "get_worker_output", InputSchema: map[string]any{
			"type": "object", "required": []string{"intent_id"}, "properties": map[string]any{"intent_id": map[string]any{"type": "integer"}},
		}}},
	}
}

func TestOpenAIWireParsesDSMLBatchGetWorkerOutput(t *testing.T) {
	for _, stream := range []bool{true, false} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			var raw string
			if stream {
				body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": llmwire.LeakedDSMLBatchFixture}}}})
				raw = "data: " + string(body) + "\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
			} else {
				body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": llmwire.LeakedDSMLBatchFixture}, "finish_reason": "stop"}}})
				raw = string(body)
			}
			prov, _, ctx := toolWireFixture(t, raw, stream)
			want := []int64{8, 9, 10, 11}
			if stream {
				acc := llm.NewAccumulator()
				for ev, err := range prov.Stream(ctx, workerOutputWireRequest()) {
					if err != nil {
						t.Fatal(err)
					}
					acc.Add(ev)
				}
				msg := acc.Message()
				for _, block := range msg.Content {
					if block.Type == llm.BlockText && strings.TrimSpace(block.Text) != "" {
						t.Fatalf("leaked content: %q", block.Text)
					}
				}
				calls := msg.ToolUses()
				if len(calls) != len(want) {
					t.Fatalf("calls=%+v", calls)
				}
				for i, call := range calls {
					if call.Name != "get_worker_output" {
						t.Fatalf("call[%d]=%+v", i, call)
					}
					var args struct {
						IntentID int64 `json:"intent_id"`
					}
					if json.Unmarshal(call.Input, &args) != nil || args.IntentID != want[i] {
						t.Fatalf("call[%d] args=%s", i, string(call.Input))
					}
				}
				return
			}
			msg, _, _, err := prov.Complete(ctx, workerOutputWireRequest())
			if err != nil {
				t.Fatal(err)
			}
			for _, block := range msg.Content {
				if block.Type == llm.BlockText && strings.TrimSpace(block.Text) != "" {
					t.Fatalf("leaked content: %q", block.Text)
				}
			}
			calls := msg.ToolUses()
			if len(calls) != len(want) {
				t.Fatalf("calls=%+v", calls)
			}
			for i, call := range calls {
				var args struct {
					IntentID int64 `json:"intent_id"`
				}
				if json.Unmarshal(call.Input, &args) != nil || args.IntentID != want[i] {
					t.Fatalf("call[%d] args=%s", i, string(call.Input))
				}
			}
		})
	}
}

func TestOpenAIWireRejectsDSMLAndBrokenArguments(t *testing.T) {
	for _, stream := range []bool{true, false} {
		for _, mode := range []string{"dsml", "broken", "wrapped"} {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, mode), func(t *testing.T) {
				message := map[string]any{"role": "assistant"}
				finish := "tool_calls"
				if mode == "dsml" {
					message["content"] = `<｜DSML｜tool_calls <｜DSML｜invoke name="get_worker_trace">`
					finish = "stop"
				} else if mode == "wrapped" {
					message["tool_calls"] = []any{map[string]any{"index": 0, "id": "a", "type": "function", "function": map[string]string{
						"name": "get_worker_trace", "arguments": `{"arguments":{"intent_id":4}}`,
					}}}
				} else {
					message["tool_calls"] = []any{map[string]any{"index": 0, "id": "a", "type": "function", "function": map[string]string{
						"name": "get_worker_trace", "arguments": `{"intent_id":`,
					}}}
				}
				var raw string
				if stream {
					body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": message}}})
					raw = "data: " + string(body) + "\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"" + finish + "\"}]}\n\ndata: [DONE]\n\n"
				} else {
					body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": message, "finish_reason": finish}}})
					raw = string(body)
				}
				prov, _, ctx := toolWireFixture(t, raw, stream)
				if mode == "wrapped" {
					if stream {
						acc := llm.NewAccumulator()
						for ev, err := range prov.Stream(ctx, toolWireRequest()) {
							if err != nil {
								t.Fatal(err)
							}
							acc.Add(ev)
						}
						calls := acc.Message().ToolUses()
						if len(calls) != 1 || string(calls[0].Input) != `{"intent_id":4}` {
							t.Fatalf("unwrap failed: %+v", calls)
						}
						return
					}
					msg, _, _, err := prov.Complete(ctx, toolWireRequest())
					if err != nil {
						t.Fatal(err)
					}
					calls := msg.ToolUses()
					if len(calls) != 1 || string(calls[0].Input) != `{"intent_id":4}` {
						t.Fatalf("unwrap failed: %+v", calls)
					}
					return
				}
				var gotErr error
				if stream {
					for ev, err := range prov.Stream(ctx, toolWireRequest()) {
						if ev.Type == llm.SEToolUseStart || ev.Type == llm.SEToolInputJSON {
							t.Fatal("invalid call reached Norma accumulator")
						}
						if err != nil {
							gotErr = err
						}
					}
				} else {
					msg, _, _, err := prov.Complete(ctx, toolWireRequest())
					gotErr = err
					if len(msg.ToolUses()) != 0 {
						t.Fatal("invalid atomic call released")
					}
				}
				if gotErr == nil || !strings.Contains(gotErr.Error(), "openai tool protocol:") {
					t.Fatalf("error=%v", gotErr)
				}
			})
		}
	}
}
func TestOpenAIWireThinkingAndToolResultsRoundTrip(t *testing.T) {
	var turn int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role       string `json:"role"`
				Reasoning  string `json:"reasoning_content"`
				ToolCallID string `json:"tool_call_id"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		turn++
		w.Header().Set("Content-Type", "application/json")
		if turn == 1 {
			_, _ = io.WriteString(w, `{"choices":[{"message":{"reasoning_content":"exact reasoning","tool_calls":[{"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":4}"}}]},"finish_reason":"tool_calls"}]}`)
			return
		}
		if len(body.Messages) != 3 || body.Messages[1].Reasoning != "exact reasoning" || body.Messages[2].Role != "tool" || body.Messages[2].ToolCallID != "a" {
			t.Errorf("history=%+v", body.Messages)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"done"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()
	cfg := ConfigFrom("openai", "deepseek-v4-flash", srv.URL, "fixture-key", "")
	cfg.ThinkingType = "enabled"
	prov, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	req := toolWireRequest()
	msg, _, _, err := prov.Complete(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.Messages = append(req.Messages, msg, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("a", "fictional trace", false)}})
	final, _, _, err := prov.Complete(context.Background(), req)
	if err != nil || final.Text() != "done" {
		t.Fatalf("final=%+v err=%v", final, err)
	}
}

// Alias and duplicate fixtures must remain raw JSON: a map would erase the
// ambiguity before either the shim or Norma sees it.
func TestOpenAIWireRejectsAmbiguousStructure(t *testing.T) {
	for _, stream := range []bool{true, false} {
		key := "message"
		if stream {
			key = "delta"
		}
		canonical := `{"choices":[{"index":0,"` + key + `":{"content":"ok","tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":4}"}}]},"finish_reason":"stop"}]}`
		for _, field := range []string{"choices", key, "content", "tool_calls", "function", "arguments", "finish_reason"} {
			for _, duplicate := range []bool{false, true} {
				t.Run(fmt.Sprintf("stream=%t/%s/duplicate=%t", stream, field, duplicate), func(t *testing.T) {
					token := `"` + field + `":`
					replacement := `"` + strings.ToUpper(field) + `":`
					if duplicate {
						replacement = token + `null,` + replacement
					}
					raw := strings.Replace(canonical, token, replacement, 1)
					if stream {
						raw = "data: " + raw + "\n\ndata: [DONE]\n\n"
					}
					prov, _, ctx := toolWireFixture(t, raw, stream)
					assertWireRejected(t, prov, ctx, toolWireRequest(), stream, "noncanonical_structural_key")
				})
			}
		}
	}
	// Exact duplicates can merge in a struct but replace in a map. A valid last
	// value must not hide a malformed first value from the boundary check.
	for _, stream := range []bool{true, false} {
		t.Run(fmt.Sprintf("exact duplicate/stream=%t", stream), func(t *testing.T) {
			key := "message"
			if stream {
				key = "delta"
			}
			raw := `{"choices":[{"` + key + `":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":"}}]},"` + key + `":{},"finish_reason":"stop"}]}`
			if stream {
				raw = "data: " + raw + "\n\ndata: [DONE]\n\n"
			}
			prov, _, ctx := toolWireFixture(t, raw, stream)
			assertWireRejected(t, prov, ctx, toolWireRequest(), stream, "duplicate_structural_key")
		})
	}
	// This is the reported bypass: Norma accepted Choices and fabricated {} from
	// its broken arguments while the old shim only saw a normal lowercase stop.
	raw := `data: {"Choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":"}}]}}]}` + "\n\n" + `data: {"choices":[{"delta":{},"finish_reason":"stop"}]}` + "\n\ndata: [DONE]\n\n"
	prov, _, ctx := toolWireFixture(t, raw, true)
	assertWireRejected(t, prov, ctx, toolWireRequest(), true, "noncanonical_structural_key")
}

func assertWireRejected(t *testing.T, prov llm.Provider, ctx context.Context, req llm.CompletionRequest, stream bool, code string) {
	t.Helper()
	var gotErr error
	if stream {
		for ev, err := range prov.Stream(ctx, req) {
			if ev.Type == llm.SEToolUseStart || ev.Type == llm.SEToolInputJSON {
				t.Fatal("invalid call reached Norma accumulator")
			}
			if err != nil {
				gotErr = err
			}
		}
	} else {
		msg, _, _, err := prov.Complete(ctx, req)
		gotErr = err
		if len(msg.ToolUses()) != 0 {
			t.Fatal("invalid atomic call released")
		}
	}
	if gotErr == nil || !strings.Contains(gotErr.Error(), code) {
		t.Fatalf("error=%v, want %s", gotErr, code)
	}
}

func TestOpenAIWireRequiresStreamIndex(t *testing.T) {
	for _, index := range []string{"", `"index":null,`} {
		t.Run(index, func(t *testing.T) {
			raw := `data: {"choices":[{"delta":{"tool_calls":[{"` + `index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":"}}]}}]}` + "\n\n" +
				`data: {"choices":[{"delta":{"tool_calls":[{` + index + `"function":{"arguments":"4}"}}]}}]}` + "\n\n" +
				`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}` + "\n\ndata: [DONE]\n\n"
			prov, _, ctx := toolWireFixture(t, raw, true)
			assertWireRejected(t, prov, ctx, toolWireRequest(), true, "missing_tool_index")
		})
	}
}

func TestOpenAIWireRequiredNullability(t *testing.T) {
	for _, stream := range []bool{true, false} {
		for _, nullable := range []bool{true, false} {
			t.Run(fmt.Sprintf("stream=%t/nullable=%t", stream, nullable), func(t *testing.T) {
				key := "message"
				if stream {
					key = "delta"
				}
				raw := `{"choices":[{"` + key + `":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":null}"}}]},"finish_reason":"tool_calls"}]}`
				if stream {
					raw = "data: " + raw + "\n\ndata: [DONE]\n\n"
				}
				prov, _, ctx := toolWireFixture(t, raw, stream)
				req := toolWireRequest()
				if !nullable {
					assertWireRejected(t, prov, ctx, req, stream, "null_required_tool_argument")
					return
				}
				req.Tools[0].InputSchema["properties"] = map[string]any{"intent_id": map[string]any{"type": []string{"integer", "null"}}}
				var msg llm.Message
				if stream {
					acc := llm.NewAccumulator()
					for ev, err := range prov.Stream(ctx, req) {
						if err != nil {
							t.Fatal(err)
						}
						acc.Add(ev)
					}
					msg = acc.Message()
				} else {
					var err error
					msg, _, _, err = prov.Complete(ctx, req)
					if err != nil {
						t.Fatal(err)
					}
				}
				calls := msg.ToolUses()
				if len(calls) != 1 || string(calls[0].Input) != `{"intent_id":null}` {
					t.Fatalf("nullable input lost: %+v", calls)
				}
			})
		}
	}
}
