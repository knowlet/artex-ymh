package llmwire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var testRules = map[string]argumentRules{
	"get_worker_trace":  {Required: []string{"intent_id"}, Properties: map[string]json.RawMessage{"intent_id": json.RawMessage(`{"type":"integer"}`)}},
	"get_worker_output": {Required: []string{"intent_id"}, Properties: map[string]json.RawMessage{"intent_id": json.RawMessage(`{"type":"integer"}`)}},
	"ping":              {},
	"literal":           {Required: []string{"arguments"}},
}

func testCall(index int, id, name, args string) wireCall {
	call := wireCall{Index: &index, ID: id, Type: "function"}
	call.Function.Name, call.Function.Arguments = name, args
	return call
}
func frame(delta any, finish any) string {
	raw, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}})
	if err != nil {
		panic(err)
	}
	return "data: " + string(raw) + "\n\n"
}
func callsFrame(calls ...wireCall) string { return frame(map[string]any{"tool_calls": calls}, nil) }
func terminal(reason string) string       { return frame(map[string]any{}, reason) + "data: [DONE]\n\n" }
func normalizeStream(text string) (string, error) {
	body := newStreamBody(io.NopCloser(strings.NewReader(text)), testRules)
	defer body.Close()
	raw, err := io.ReadAll(body)
	return string(raw), err
}

// Consume normalized SSE using Norma v0.4.3's index-blind association rule.
// If calls aren't emitted contiguously, this helper observes the same corruption.
func legacyCalls(t *testing.T, s string) (calls []wireCall, text, reasoning string) {
	t.Helper()
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
			continue
		}
		var f struct {
			Choices []struct {
				Delta struct {
					Content   string     `json:"content"`
					Reasoning string     `json:"reasoning_content"`
					Calls     []wireCall `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &f); err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Choices {
			text += c.Delta.Content
			reasoning += c.Delta.Reasoning
			for _, call := range c.Delta.Calls {
				if call.ID != "" || call.Function.Name != "" {
					fresh := call
					fresh.Function.Arguments = ""
					calls = append(calls, fresh)
				}
				if n := len(calls); n > 0 {
					calls[n-1].Function.Arguments += call.Function.Arguments
				}
			}
		}
	}
	return
}
func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	var p *ProtocolError
	if !errors.As(err, &p) || p.Code != code {
		t.Fatalf("error=%v, want %s", err, code)
	}
}
func TestInterleavedToolArguments(t *testing.T) {
	a, b := testCall(0, "a", "get_worker_trace", `{"intent_id":`), testCall(1, "b", "get_worker_trace", `{"intent_id":`)
	aEnd, bEnd := testCall(0, "", "", `4}`), testCall(1, "", "", `9}`)
	out, err := normalizeStream(callsFrame(a, b) + callsFrame(aEnd, bEnd) + terminal("tool_calls"))
	if err != nil {
		t.Fatal(err)
	}
	got, _, _ := legacyCalls(t, out)
	want := []wireCall{testCall(0, "a", "get_worker_trace", `{"intent_id":4}`), testCall(1, "b", "get_worker_trace", `{"intent_id":9}`)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("calls=%+v want=%+v", got, want)
	}
}
func TestDelayedAndFragmentedName(t *testing.T) {
	for _, names := range [][]string{{"", "get_worker_trace"}, {"get_", "worker_", "trace"}} {
		t.Run(strings.Join(names, "/"), func(t *testing.T) {
			s := callsFrame(testCall(3, "a", "", ""))
			for _, name := range names {
				s += callsFrame(testCall(3, "", name, ""))
			}
			s += callsFrame(testCall(3, "", "", `{"intent_id":4}`)) + terminal("tool_calls")
			out, err := normalizeStream(s)
			if err != nil {
				t.Fatal(err)
			}
			got, _, _ := legacyCalls(t, out)
			if len(got) != 1 || got[0].Function.Name != "get_worker_trace" || (got[0].Index == nil || *got[0].Index != 3) {
				t.Fatalf("calls=%+v", got)
			}
		})
	}
}
func TestProtocolErrorTransientClassification(t *testing.T) {
	transient := []string{"missing_finish_reason", "upstream_stream_error"}
	for _, code := range transient {
		if err := protocolTransientError(code, io.EOF); err.(*ProtocolError).Transient() != true {
			t.Fatalf("%s must be transient", code)
		}
	}
	nonTransient := []string{"invalid_tool_arguments", "unparsed_dsml_tool_call", "missing_required_tool_argument"}
	for _, code := range nonTransient {
		if err := protocolError(code); err.(*ProtocolError).Transient() {
			t.Fatalf("%s must not be transient", code)
		}
	}
}

func TestStreamFailuresNeverReleaseToolCalls(t *testing.T) {
	good := callsFrame(testCall(0, "a", "get_worker_trace", `{"intent_id":4}`))
	cases := []struct{ name, input, code string }{
		{"truncated JSON", callsFrame(testCall(0, "a", "get_worker_trace", `{"intent_id":`)) + terminal("tool_calls"), "invalid_tool_arguments"},
		{"missing required", callsFrame(testCall(0, "a", "get_worker_trace", `{}`)) + terminal("tool_calls"), "missing_required_tool_argument"},
		{"nested envelope", callsFrame(testCall(0, "a", "get_worker_trace", `{"arguments":"not-json"}`)) + terminal("tool_calls"), "missing_required_tool_argument"},
		{"null arguments", callsFrame(testCall(0, "a", "get_worker_trace", `null`)) + terminal("tool_calls"), "invalid_tool_arguments"},
		{"array arguments", callsFrame(testCall(0, "a", "get_worker_trace", `[]`)) + terminal("tool_calls"), "invalid_tool_arguments"},
		{"missing arguments", callsFrame(testCall(0, "a", "get_worker_trace", ``)) + terminal("tool_calls"), "invalid_tool_arguments"},
		{"length", good + terminal("length"), "incomplete_tool_turn"},
		{"filtered", good + terminal("content_filter"), "incomplete_tool_turn"},
		{"EOF", good, "missing_finish_reason"},
		{"DONE without finish", good + "data: [DONE]\n\n", "missing_finish_reason"},
		{"unknown tool", callsFrame(testCall(0, "a", "unknown", `{}`)) + terminal("tool_calls"), "undeclared_tool"},
		{"duplicate IDs", callsFrame(testCall(0, "a", "ping", `{}`), testCall(1, "a", "ping", `{}`)) + terminal("tool_calls"), "invalid_tool_id"},
		{"identity mutation", good + callsFrame(testCall(0, "b", "", "")) + terminal("tool_calls"), "conflicting_tool_id"},
		{"negative index", callsFrame(testCall(-1, "a", "ping", `{}`)) + terminal("tool_calls"), "invalid_tool_index"},
		{"large index", callsFrame(testCall(maxToolCalls, "a", "ping", `{}`)) + terminal("tool_calls"), "invalid_tool_index"},
		{"missing calls", terminal("tool_calls"), "missing_tool_calls"},
		{"null choice", good + "data: {\"choices\":[null]}\n\n" + terminal("tool_calls"), "invalid_stream_choice"},
		{"malformed frame", good + "data: {broken}\n\n" + terminal("tool_calls"), "invalid_sse_json"},
		{"error frame", good + "data: {\"error\":{\"message\":\"no secret body in error\"}}\n\n", "upstream_stream_error"},
		{"late error", good + frame(map[string]any{}, "tool_calls") + "data: {\"error\":{\"message\":\"late\"}}\n\n", "upstream_stream_error"},
		{"late args", good + frame(map[string]any{}, "tool_calls") + good + "data: [DONE]\n\n", "data_after_finish"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := normalizeStream(tc.input)
			expectCode(t, err, tc.code)
			got, _, _ := legacyCalls(t, out)
			if len(got) != 0 {
				t.Fatalf("failed response released executable calls: %+v", got)
			}
		})
	}
}
func TestDSMLSplitAtEveryRune(t *testing.T) {
	raw := []rune(`<｜DSML｜tool_calls <｜DSML｜invoke name="get_worker_trace">`)
	for i := 0; i <= len(raw); i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			out, err := normalizeStream(frame(map[string]string{"content": string(raw[:i])}, nil) + frame(map[string]string{"content": string(raw[i:])}, nil) + terminal("stop"))
			expectCode(t, err, "unparsed_dsml_tool_call")
			_, text, _ := legacyCalls(t, out)
			if text != "" {
				t.Fatalf("DSML prefix escaped: %q", text)
			}
		})
	}
}
func TestDSMLInRefusalStream(t *testing.T) {
	raw := []rune(`<｜DSML｜tool_calls <｜DSML｜invoke name="get_worker_trace">`)
	for i := 0; i <= len(raw); i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			_, err := normalizeStream(frame(map[string]string{"refusal": string(raw[:i])}, nil) + frame(map[string]string{"refusal": string(raw[i:])}, nil) + terminal("stop"))
			expectCode(t, err, "unparsed_dsml_tool_call")
		})
	}
	_, err := normalizeStream(frame(map[string]string{"refusal": "<｜DSML"}, nil) + terminal("stop"))
	expectCode(t, err, "unparsed_dsml_tool_call")
}

func TestTruncatedDSMLAndTrailingLessThan(t *testing.T) {
	_, err := normalizeStream(frame(map[string]string{"content": "<｜DSML"}, nil) + terminal("stop"))
	expectCode(t, err, "unparsed_dsml_tool_call")
	out, err := normalizeStream(frame(map[string]string{"content": "a <"}, nil) + terminal("stop"))
	if err != nil {
		t.Fatal(err)
	}
	_, text, _ := legacyCalls(t, out)
	if text != "a <" {
		t.Fatalf("text=%q", text)
	}
}
func TestReasoningUsageAndLiteralArgumentsPreserved(t *testing.T) {
	literal := `{"arguments":"<｜DSML｜invoke name=\"example\">"}`
	s := frame(map[string]string{"reasoning_content": "Considering <｜DSML｜tool_calls> internally", "content": "working"}, nil)
	s += callsFrame(testCall(0, "a", "literal", literal))
	s += frame(map[string]any{}, "tool_calls")
	s += "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":8}}\n\ndata: [DONE]\n\n"
	out, err := normalizeStream(s)
	if err != nil {
		t.Fatal(err)
	}
	calls, text, reasoning := legacyCalls(t, out)
	if text != "working" || reasoning != "Considering <｜DSML｜tool_calls> internally" || len(calls) != 1 || calls[0].Function.Arguments != literal {
		t.Fatalf("lost content: %q %q %+v", text, reasoning, calls)
	}
	if !strings.Contains(out, `"completion_tokens":8`) {
		t.Fatal("usage lost")
	}
}
func TestEOFWithTerminalFrameAndZeroArgumentTool(t *testing.T) {
	for _, args := range []string{"", `{}`} {
		out, err := normalizeStream(callsFrame(testCall(0, "a", "ping", args)) + strings.TrimSpace(frame(map[string]any{}, "tool_calls")))
		if err != nil {
			t.Fatal(err)
		}
		calls, _, _ := legacyCalls(t, out)
		if len(calls) != 1 {
			t.Fatal("zero-argument tool lost")
		}
	}
}
func complete(calls []wireCall, content, finish string) []byte {
	return completeMessage(calls, content, "", finish)
}

func completeMessage(calls []wireCall, content, refusal, finish string) []byte {
	msg := map[string]any{"content": content, "tool_calls": calls}
	if refusal != "" {
		msg["refusal"] = refusal
	}
	raw, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": msg, "finish_reason": finish}}})
	if err != nil {
		panic(err)
	}
	return raw
}
func TestCompleteValidation(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		code string
	}{
		{"valid", complete([]wireCall{testCall(0, "a", "get_worker_trace", `{"intent_id":4}`)}, "", "tool_calls"), ""},
		{"prose", complete(nil, "normal answer", "stop"), ""},
		{"DSML", complete(nil, `<｜DSML｜tool_calls <｜DSML｜invoke name="get_worker_trace">`, "stop"), "unparsed_dsml_tool_call"},
		{"DSML refusal", completeMessage(nil, "", `<｜DSML｜tool_calls <｜DSML｜invoke name="get_worker_trace">`, "stop"), "unparsed_dsml_tool_call"},
		{"broken arguments", complete([]wireCall{testCall(0, "a", "get_worker_trace", `{"intent_id":`)}, "", "tool_calls"), "invalid_tool_arguments"},
		{"wrapped unwrapped", complete([]wireCall{testCall(0, "a", "get_worker_trace", `{"arguments":{"intent_id":4}}`)}, "", "tool_calls"), ""},
		{"legitimate arguments property", complete([]wireCall{testCall(0, "a", "literal", `{"arguments":{"intent_id":4}}`)}, "", "tool_calls"), ""},
		{"length", complete([]wireCall{testCall(0, "a", "get_worker_trace", `{"intent_id":4}`)}, "", "length"), "incomplete_tool_turn"},
		{"upstream error", []byte(`{"error":{"message":"preserve SDK error"}}`), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := normalizeComplete(tc.raw, testRules)
			if tc.code != "" {
				expectCode(t, err, tc.code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "wrapped unwrapped" {
				var env struct {
					Choices []struct {
						Message struct {
							ToolCalls []struct {
								Function struct {
									Arguments string `json:"arguments"`
								} `json:"function"`
							} `json:"tool_calls"`
						} `json:"message"`
					} `json:"choices"`
				}
				if err := json.Unmarshal(out, &env); err != nil || len(env.Choices) == 0 || len(env.Choices[0].Message.ToolCalls) == 0 {
					t.Fatalf("parse: %v", err)
				}
				if got := env.Choices[0].Message.ToolCalls[0].Function.Arguments; got != `{"intent_id":4}` {
					t.Fatalf("arguments=%q", got)
				}
				return
			}
			if !bytes.Equal(out, tc.raw) {
				t.Fatalf("response changed: %s %v", out, err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func request(t *testing.T, stream, tools bool) *http.Request {
	t.Helper()
	body := fmt.Sprintf(`{"model":"deepseek-v4-flash","stream":%t,"messages":[{"role":"user","content":"fixture"}]`, stream)
	if tools {
		body += `,"tools":[{"type":"function","function":{"name":"get_worker_trace","parameters":{"type":"object","required":["intent_id"]}}}]`
	}
	req, err := http.NewRequest(http.MethodPost, "https://model.example/v1/chat/completions", strings.NewReader(body+"}"))
	if err != nil {
		t.Fatal(err)
	}
	return req
}
func TestTransportPreservesRequestAndRawCapture(t *testing.T) {
	raw := callsFrame(testCall(0, "a", "get_worker_trace", `{"intent_id":4}`)) + terminal("tool_calls")
	var captured bytes.Buffer
	var sent string
	inner := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		sent = string(b)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": []string{fmt.Sprint(len(raw))}}, Body: io.NopCloser(io.TeeReader(strings.NewReader(raw), &captured))}, nil
	})
	req := request(t, true, true)
	snapshot, _ := req.GetBody()
	expected, _ := io.ReadAll(snapshot)
	snapshot.Close()
	resp, err := Wrap(inner).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if captured.String() != raw || sent != string(expected) {
		t.Fatal("raw recording or request mutated")
	}
	if resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "" {
		t.Fatal("stale body length")
	}
	calls, _, _ := legacyCalls(t, string(out))
	if len(calls) != 1 {
		t.Fatal("call lost")
	}
}
func TestPassthroughScoping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tools  bool
		path   string
		status int
	}{
		{"no tools", false, "/v1/chat/completions", 200},
		{"responses", true, "/v1/responses", 200},
		{"anthropic", true, "/v1/messages", 200},
		{"quota", true, "/v1/chat/completions", 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "untouched <｜DSML｜tool_calls>"
			inner := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(raw))}, nil
			})
			req := request(t, true, tc.tools)
			req.URL.Path = tc.path
			resp, err := Wrap(inner).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil || string(got) != raw {
				t.Fatalf("changed: %q %v", got, err)
			}
		})
	}
}
func TestCompleteTransportLazyValidation(t *testing.T) {
	raw := complete(nil, "<｜DSML｜tool_calls>", "stop")
	inner := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}, nil
	})
	resp, err := Wrap(inner).RoundTrip(request(t, false, true))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	expectCode(t, err, "unparsed_dsml_tool_call")
}
func TestTextRemainsStreaming(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	body := newStreamBody(reader, testRules)
	defer body.Close()
	sent := make(chan struct{})
	go func() { _, _ = io.WriteString(writer, frame(map[string]string{"content": "hello"}, nil)); close(sent) }()
	result := make(chan error, 1)
	go func() {
		p := make([]byte, 2048)
		n, err := body.Read(p)
		if err == nil && !bytes.Contains(p[:n], []byte("hello")) {
			err = fmt.Errorf("no text: %s", p[:n])
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("text buffered waiting for completion")
	}
	<-sent
}
func TestContextCancellationAndEarlyClose(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := request(t, true, true).WithContext(ctx)
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
	client := http.Client{Transport: Wrap(http.DefaultTransport)}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-started
	cancel()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("cancellation ignored")
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("underlying request not canceled")
	}
}
func TestConcurrentResponsesHaveIndependentState(t *testing.T) {
	var wg sync.WaitGroup
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s := callsFrame(testCall(0, fmt.Sprint(n), "get_worker_trace", fmt.Sprintf(`{"intent_id":%d}`, n))) + terminal("tool_calls")
			out, err := normalizeStream(s)
			if err != nil {
				t.Errorf("n=%d: %v", n, err)
				return
			}
			calls, _, _ := legacyCalls(t, out)
			want := fmt.Sprintf(`{"intent_id":%d}`, n)
			if len(calls) != 1 || calls[0].ID != fmt.Sprint(n) || calls[0].Function.Arguments != want {
				t.Errorf("n=%d: calls=%+v, want exact arguments %s", n, calls, want)
			}
		}(n)
	}
	wg.Wait()
}
func TestValidateCallsUnwrapsProviderEnvelopeForRequiredTools(t *testing.T) {
	base := `{"vulnclass":"sqli","severity":"high","summary":"fixture","evidence":"poc"}`
	wrapped := base
	for range 2 {
		var err error
		wrapped, err = wrapFixtureArguments(wrapped, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	rules := map[string]argumentRules{
		"report_finding": {Required: []string{"vulnclass", "severity", "summary"}, Properties: map[string]json.RawMessage{
			"vulnclass": json.RawMessage(`{"type":"string"}`),
			"severity":  json.RawMessage(`{"type":"string"}`),
			"summary":   json.RawMessage(`{"type":"string"}`),
		}},
	}
	raw := string(fixtureJSON(map[string]any{"choices": []any{map[string]any{
		"message": map[string]any{
			"tool_calls": []any{map[string]any{"index": 0, "id": "wrapped-finding", "type": "function", "function": map[string]any{
				"name": "report_finding", "arguments": wrapped,
			}}},
		},
		"finish_reason": "tool_calls",
	}}}))
	body := &completeBody{source: io.NopCloser(strings.NewReader(raw)), rules: rules}
	defer body.Close()
	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					Function struct {
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &env); err != nil || len(env.Choices) == 0 || len(env.Choices[0].Message.ToolCalls) == 0 {
		t.Fatalf("response parse failed: %v", err)
	}
	got := env.Choices[0].Message.ToolCalls[0].Function.Arguments
	if got != base {
		t.Fatalf("arguments not unwrapped for tool handler: %q", got)
	}
}

func wrapFixtureArguments(raw string, stringify bool) (string, error) {
	var value any = json.RawMessage(raw)
	if stringify {
		value = raw
	}
	b, err := json.Marshal(map[string]any{"arguments": value})
	return string(b), err
}

func fixtureJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestLimits(t *testing.T) {
	_, err := normalizeStream(callsFrame(testCall(0, "a", "ping", strings.Repeat("x", maxBodyBytes))) + terminal("tool_calls"))
	if err == nil {
		t.Fatal("oversized frame accepted")
	}
	body := &completeBody{source: io.NopCloser(strings.NewReader(strings.Repeat("x", maxBodyBytes+1))), rules: testRules}
	defer body.Close()
	_, err = io.ReadAll(body)
	expectCode(t, err, "response_too_large")
}

// Fuzzing checks parser safety only; it never invokes tools or external services.
func FuzzStreamBoundary(f *testing.F) {
	f.Add(callsFrame(testCall(0, "a", "get_worker_trace", `{"intent_id":4}`)) + terminal("tool_calls"))
	f.Add("data: {\"choices\":[null]}\n\n")
	f.Add("data: {\"choices\":[{\"delta\":{\"content\":\"<｜DSML｜tool_calls\"}}]}\n\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			t.Skip()
		}
		_, _ = normalizeStream(s)
	})
}
