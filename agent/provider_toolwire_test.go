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
func TestOpenAIWireRejectsDSMLAndBrokenArguments(t *testing.T) {
	for _, stream := range []bool{true, false} {
		for _, mode := range []string{"dsml", "broken", "wrapped"} {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, mode), func(t *testing.T) {
				message := map[string]any{"role": "assistant"}
				finish := "tool_calls"
				if mode == "dsml" {
					message["content"] = `<｜DSML｜tool_calls <｜DSML｜invoke name="get_worker_trace">`
					finish = "stop"
				} else {
					args := `{"intent_id":`
					if mode == "wrapped" {
						args = `{"arguments":{"intent_id":4}}`
					}
					message["tool_calls"] = []any{map[string]any{"index": 0, "id": "a", "type": "function", "function": map[string]string{"name": "get_worker_trace", "arguments": args}}}
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
