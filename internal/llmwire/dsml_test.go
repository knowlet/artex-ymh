package llmwire

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

var dsmlRules = map[string]argumentRules{
	"get_worker_output": {Required: []string{"intent_id"}, Properties: map[string]json.RawMessage{"intent_id": json.RawMessage(`{"type":"integer"}`)}},
	"get_worker_trace":  {Required: []string{"intent_id"}, Properties: map[string]json.RawMessage{"intent_id": json.RawMessage(`{"type":"integer"}`)}},
	"ping":              {},
}

func TestDSMLBatchGetWorkerOutputLeakFixture(t *testing.T) {
	_, _, calls, err := extractDSMLToolCalls(LeakedDSMLBatchFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 {
		t.Fatalf("calls=%d", len(calls))
	}
	wantIDs := []int64{8, 9, 10, 11}
	for i, call := range calls {
		if call.Function.Name != "get_worker_output" {
			t.Fatalf("call[%d] name=%q", i, call.Function.Name)
		}
		var args struct {
			IntentID int64 `json:"intent_id"`
		}
		if json.Unmarshal([]byte(call.Function.Arguments), &args) != nil || args.IntentID != wantIDs[i] {
			t.Fatalf("call[%d] args=%s", i, call.Function.Arguments)
		}
	}
	out, err := normalizeStream(frame(map[string]string{"content": LeakedDSMLBatchFixture}, nil) + terminal("stop"))
	if err != nil {
		t.Fatal(err)
	}
	got, text, _ := legacyCalls(t, out)
	if text != "" {
		t.Fatalf("DSML leaked into content: %q", text)
	}
	if len(got) != 4 {
		t.Fatalf("stream calls=%+v", got)
	}
	for i, want := range wantIDs {
		var args struct {
			IntentID int64 `json:"intent_id"`
		}
		_ = json.Unmarshal([]byte(got[i].Function.Arguments), &args)
		if got[i].Function.Name != "get_worker_output" || args.IntentID != want {
			t.Fatalf("call[%d]=%+v", i, got[i])
		}
	}
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
	if envelope.Choices[0].Message.Content != "" || envelope.Choices[0].Finish != "tool_calls" || len(envelope.Choices[0].Message.ToolCalls) != 4 {
		t.Fatalf("atomic rewrite failed: %+v", envelope.Choices[0])
	}
}

func TestDSMLSingleInvokeAndStringParameter(t *testing.T) {
	raw := `<｜DSML｜tool_calls><｜DSML｜invoke name="ping"><｜DSML｜parameter name="note" string="true">hello</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	_, _, calls, err := extractDSMLToolCalls(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].Function.Name != "ping" {
		t.Fatalf("calls=%+v", calls)
	}
}

func TestDSMLMalformedStillLeakage(t *testing.T) {
	cases := []string{
		`<｜DSML｜tool_calls <｜DSML｜invoke name="get_worker_trace">`,
		`<｜DSML｜invoke name="get_worker_output">`,
		`prefix <｜DSML｜tool_calls> partial`,
	}
	for _, raw := range cases {
		t.Run(fmt.Sprintf("%d", len(raw)), func(t *testing.T) {
			_, err := normalizeStream(frame(map[string]string{"content": raw}, nil) + terminal("stop"))
			expectCode(t, err, "unparsed_dsml_tool_call")
		})
	}
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
	if text != "" || len(got) != 4 {
		t.Fatalf("text=%q calls=%+v", text, got)
	}
}

func TestDSMLIntegerCoercionVsString(t *testing.T) {
	raw := `<｜DSML｜tool_calls><｜DSML｜invoke name="get_worker_output"><｜DSML｜parameter name="intent_id" string="false">42</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	_, _, calls, err := extractDSMLToolCalls(raw)
	if err != nil {
		t.Fatal(err)
	}
	var args map[string]any
	if json.Unmarshal([]byte(calls[0].Function.Arguments), &args) != nil {
		t.Fatal()
	}
	if v, ok := args["intent_id"].(float64); !ok || int64(v) != 42 {
		t.Fatalf("coercion=%v", args["intent_id"])
	}
	strRaw := `<｜DSML｜tool_calls><｜DSML｜invoke name="literal"><｜DSML｜parameter name="arguments" string="true">not-json</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	_, _, strCalls, err := extractDSMLToolCalls(strRaw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"arguments": "not-json"}
	var got map[string]any
	_ = json.Unmarshal([]byte(strCalls[0].Function.Arguments), &got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("string param=%v", got)
	}
}
