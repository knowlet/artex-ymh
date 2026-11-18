package llmwire

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

var dsmlRules = map[string]argumentRules{
	"get_worker_output": {Required: []string{"intent_id"}, Properties: map[string]json.RawMessage{"intent_id": json.RawMessage(`{"type":"integer"}`)}},
	"get_worker_trace":  {Required: []string{"intent_id"}, Properties: map[string]json.RawMessage{"intent_id": json.RawMessage(`{"type":"integer"}`)}},
	"ping":              {},
}

func assertWorkerOutputBatchCalls(t *testing.T, calls []wireCall) {
	t.Helper()
	wantIDs := []int64{8, 9, 10, 11}
	if len(calls) != len(wantIDs) {
		t.Fatalf("calls=%+v", calls)
	}
	for i, call := range calls {
		if call.Function.Name != "get_worker_output" {
			t.Fatalf("call[%d] name=%q", i, call.Function.Name)
		}
		if call.Function.Arguments != fmt.Sprintf(`{"intent_id":%d}`, wantIDs[i]) {
			t.Fatalf("call[%d] args=%q want intent_id %d", i, call.Function.Arguments, wantIDs[i])
		}
	}
}

func TestDSMLBatchGetWorkerOutputLeakFixture(t *testing.T) {
	_, _, calls, err := extractDSMLToolCalls(LeakedDSMLBatchFixture)
	if err != nil {
		t.Fatal(err)
	}
	assertWorkerOutputBatchCalls(t, calls)
	out, err := normalizeStream(frame(map[string]string{"content": LeakedDSMLBatchFixture}, nil) + terminal("stop"))
	if err != nil {
		t.Fatal(err)
	}
	got, text, _ := legacyCalls(t, out)
	if text != "" {
		t.Fatalf("DSML leaked into content: %q", text)
	}
	assertWorkerOutputBatchCalls(t, got)
	raw := complete(nil, LeakedDSMLBatchFixture, "stop")
	atomic, err := normalizeComplete(raw, dsmlRules)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Choices []struct {
			Message struct {
				Content   string     `json:"content"`
				ToolCalls []wireCall `json:"tool_calls"`
			} `json:"message"`
			Finish string `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(atomic, &envelope) != nil {
		t.Fatal(err)
	}
	if envelope.Choices[0].Message.Content != "" || envelope.Choices[0].Finish != "tool_calls" {
		t.Fatalf("atomic rewrite failed: %+v", envelope.Choices[0])
	}
	assertWorkerOutputBatchCalls(t, envelope.Choices[0].Message.ToolCalls)
}

func TestDSMLSingleInvokeAndStringParameter(t *testing.T) {
	raw := `<｜DSML｜tool_calls><｜DSML｜invoke name="ping"><｜DSML｜parameter name="note" string="true">hello</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	_, _, calls, err := extractDSMLToolCalls(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].Function.Name != "ping" || calls[0].Function.Arguments != `{"note":"hello"}` {
		t.Fatalf("calls=%+v", calls)
	}
}

func TestDSMLMalformedStillLeakage(t *testing.T) {
	cases := []string{
		`<｜DSML｜tool_calls <｜DSML｜invoke name="get_worker_trace">`,
		`<｜DSML｜invoke name="get_worker_output">`,
		`prefix <｜DSML｜tool_calls> partial`,
		`<｜DSML｜tool_calls><｜DSML｜invoke name="ping"></｜DSML｜invoke>oops<｜DSML｜invoke name="ping"></｜DSML｜invoke></｜DSML｜tool_calls>`,
		`<｜DSML｜tool_calls><｜DSML｜invoke name="ping"><｜DSML｜parameter name="a" string="false">1</｜DSML｜parameter><｜DSML｜parameter name="a" string="false">2</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`,
	}
	for _, raw := range cases {
		t.Run(fmt.Sprintf("%d", len(raw)), func(t *testing.T) {
			_, err := normalizeStream(frame(map[string]string{"content": raw}, nil) + terminal("stop"))
			expectCode(t, err, "unparsed_dsml_tool_call")
		})
	}
}

func TestDSMLQuotedEnvelopeDoesNotExecute(t *testing.T) {
	quoted := "For example:\n" + LeakedDSMLBatchFixture
	_, err := normalizeStream(frame(map[string]string{"content": quoted}, nil) + terminal("stop"))
	expectCode(t, err, "unparsed_dsml_tool_call")
	raw := complete(nil, quoted, "stop")
	_, err = normalizeComplete(raw, dsmlRules)
	expectCode(t, err, "unparsed_dsml_tool_call")
}

func TestDSMLRefusalNeverExecutesTools(t *testing.T) {
	_, err := normalizeStream(frame(map[string]string{"refusal": LeakedDSMLBatchFixture}, nil) + terminal("stop"))
	expectCode(t, err, "unparsed_dsml_tool_call")
	raw := completeMessage(nil, "", LeakedDSMLBatchFixture, "stop")
	_, err = normalizeComplete(raw, dsmlRules)
	expectCode(t, err, "unparsed_dsml_tool_call")
}

func TestAtomicDSMLPreservesReasoningMetadata(t *testing.T) {
	msg := map[string]any{
		"content":           LeakedDSMLBatchFixture,
		"reasoning_content": "reasoning survives",
		"role":              "assistant",
	}
	raw, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": msg, "finish_reason": "stop"}}, "model": "deepseek-v4-flash"})
	out, err := normalizeComplete(raw, dsmlRules)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Choices []struct {
			Message struct {
				Content   string     `json:"content"`
				Reasoning string     `json:"reasoning_content"`
				Role      string     `json:"role"`
				ToolCalls []wireCall `json:"tool_calls"`
			} `json:"message"`
			Finish string `json:"finish_reason"`
		} `json:"choices"`
		Model string `json:"model"`
	}
	if json.Unmarshal(out, &envelope) != nil {
		t.Fatal()
	}
	if envelope.Model != "deepseek-v4-flash" || envelope.Choices[0].Message.Reasoning != "reasoning survives" ||
		envelope.Choices[0].Message.Role != "assistant" || envelope.Choices[0].Finish != "tool_calls" {
		t.Fatalf("metadata lost: %+v model=%q", envelope.Choices[0], envelope.Model)
	}
	assertWorkerOutputBatchCalls(t, envelope.Choices[0].Message.ToolCalls)
}

func TestDSMLSplitBatchAcrossChunks(t *testing.T) {
	chunks := []string{}
	runes := []rune(LeakedDSMLBatchFixture)
	step := 37
	for i := 0; i < len(runes); i += step {
		end := min(i+step, len(runes))
		chunks = append(chunks, string(runes[i:end]))
	}
	s := ""
	for _, chunk := range chunks {
		s += frame(map[string]string{"content": chunk}, nil)
	}
	s += terminal("stop")
	out, err := normalizeStream(s)
	if err != nil {
		t.Fatal(err)
	}
	got, text, _ := legacyCalls(t, out)
	if text != "" {
		t.Fatalf("text=%q", text)
	}
	assertWorkerOutputBatchCalls(t, got)
}

func TestDSMLCaptureSizeLimit(t *testing.T) {
	chunk := strings.Repeat("x", 64<<10)
	s := frame(map[string]string{"content": dsmlToolCallsOpen}, nil)
	for i := 0; i < (maxBodyBytes/len(chunk))+2; i++ {
		s += frame(map[string]string{"content": chunk}, nil)
	}
	s += terminal("stop")
	_, err := normalizeStream(s)
	expectCode(t, err, "unparsed_dsml_tool_call")
}

func TestDSMLIntegerCoercionVsString(t *testing.T) {
	raw := `<｜DSML｜tool_calls><｜DSML｜invoke name="get_worker_output"><｜DSML｜parameter name="intent_id" string="false">42</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	_, _, calls, err := extractDSMLToolCalls(raw)
	if err != nil {
		t.Fatal(err)
	}
	if calls[0].Function.Arguments != `{"intent_id":42}` {
		t.Fatalf("args=%s", calls[0].Function.Arguments)
	}
	big := "9007199254740993"
	bigRaw := `<｜DSML｜tool_calls><｜DSML｜invoke name="get_worker_output"><｜DSML｜parameter name="intent_id" string="false">` + big + `</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	_, _, bigCalls, err := extractDSMLToolCalls(bigRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bigCalls[0].Function.Arguments, big) {
		t.Fatalf("precision lost: %s", bigCalls[0].Function.Arguments)
	}
	strRaw := `<｜DSML｜tool_calls><｜DSML｜invoke name="literal"><｜DSML｜parameter name="arguments" string="true">not-json</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	_, _, strCalls, err := extractDSMLToolCalls(strRaw)
	if err != nil {
		t.Fatal(err)
	}
	if strCalls[0].Function.Arguments != `{"arguments":"not-json"}` {
		t.Fatalf("string param=%q", strCalls[0].Function.Arguments)
	}
	spaceRaw := `<｜DSML｜tool_calls><｜DSML｜invoke name="literal"><｜DSML｜parameter name="arguments" string="true">  keep  </｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	_, _, spaceCalls, err := extractDSMLToolCalls(spaceRaw)
	if err != nil {
		t.Fatal(err)
	}
	if spaceCalls[0].Function.Arguments != `{"arguments":"  keep  "}` {
		t.Fatalf("whitespace trimmed: %q", spaceCalls[0].Function.Arguments)
	}
}
