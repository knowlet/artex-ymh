package llmwire

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReviewMissingStreamIndex(t *testing.T) {
	for _, index := range []string{"", `"index":null,`} {
		for _, continuation := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/continuation=%t", index, continuation), func(t *testing.T) {
				call := `{` + index + `"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":4}"}}`
				prefix := ""
				if continuation {
					prefix = callsFrame(testCall(0, "a", "get_worker_trace", `{"intent_id":`))
					call = `{` + index + `"function":{"arguments":"4}"}}`
				}
				out, err := normalizeStream(prefix + `data: {"choices":[{"delta":{"tool_calls":[` + call + `]}}]}` + "\n\n" + terminal("stop"))
				if err == nil {
					t.Fatalf("index-less delta accepted: %s", out)
				}
				calls, _, _ := legacyCalls(t, out)
				if len(calls) != 0 {
					t.Fatalf("invalid call released: %+v", calls)
				}
			})
		}
	}
}

// Keep these as raw strings: marshaling a Go map would erase duplicate keys.
func TestReviewStructuralAliasesAndDuplicates(t *testing.T) {
	for _, stream := range []bool{true, false} {
		messageKey := "message"
		if stream {
			messageKey = "delta"
		}
		normal := `{"choices":[{"index":0,"` + messageKey + `":{"content":"hello","reasoning_content":"reasoning","tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":4}"}}]},"finish_reason":"stop"}]}`
		fields := []string{"choices", "index", messageKey, "content", "reasoning_content", "tool_calls", "id", "type", "function", "name", "arguments", "finish_reason"}
		for _, key := range fields {
			for _, mode := range []string{"alias", "duplicate", "mixed_before", "mixed_after"} {
				t.Run(fmt.Sprintf("stream=%t/%s/%s", stream, key, mode), func(t *testing.T) {
					token := `"` + key + `":`
					alias := `"` + strings.ToUpper(key) + `":`
					replacement := alias
					switch mode {
					case "duplicate":
						replacement = token + `null,` + token
					case "mixed_before":
						replacement = alias + `null,` + token
					case "mixed_after":
						replacement = token + `null,` + alias
					}
					raw := strings.Replace(normal, token, replacement, 1)
					var err error
					if stream {
						var out string
						out, err = normalizeStream("data: " + raw + "\n\ndata: [DONE]\n\n")
						calls, _, _ := legacyCalls(t, out)
						if len(calls) != 0 {
							t.Fatalf("bypass released calls: %+v", calls)
						}
					} else {
						_, err = normalizeComplete([]byte(raw), testRules)
					}
					if err == nil {
						t.Fatalf("structural ambiguity accepted: %s", raw)
					}
				})
			}
		}
	}
}

func TestReviewEscapedAndUnicodeAliases(t *testing.T) {
	for _, key := range []string{`Choice\u0073`, `choiceſ`, `CHOICES`} {
		raw := `data: {"` + key + `":[{"delta":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{\"intent_id\":"}}]}}]}` + "\n\n" + terminal("stop")
		out, err := normalizeStream(raw)
		if err == nil {
			t.Fatalf("alias accepted: %s", raw)
		}
		calls, _, _ := legacyCalls(t, out)
		if len(calls) != 0 {
			t.Fatalf("call escaped: %+v", calls)
		}
	}
	// JSON escapes are fine when the decoded spelling is canonical.
	raw := `data: {"choi\u0063es":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}` + "\n\ndata: [DONE]\n\n"
	out, err := normalizeStream(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, text, _ := legacyCalls(t, out)
	if text != "ok" {
		t.Fatalf("text=%q", text)
	}
}

func TestReviewArgumentKeysAreNotProtocolKeys(t *testing.T) {
	// Argument keys are tool data, not Chat Completions field names. Neither
	// case variants nor nested vendor metadata should be rewritten/rejected.
	args := `{"arguments":{"Choices":1,"choices":2,"Delta":3,"Tool_Calls":4,"Content":5}}`
	call := testCall(0, "a", "literal", args)
	raw := callsFrame(call) + terminal("tool_calls")
	out, err := normalizeStream(raw)
	if err != nil {
		t.Fatal(err)
	}
	calls, _, _ := legacyCalls(t, out)
	if len(calls) != 1 || calls[0].Function.Arguments != args {
		t.Fatalf("calls=%+v", calls)
	}
	var value any
	if json.Unmarshal([]byte(calls[0].Function.Arguments), &value) != nil {
		t.Fatal("invalid fixture")
	}
}

func TestReviewRequiredNullabilityThroughTransport(t *testing.T) {
	cases := []struct {
		name, schema string
		reject       bool
	}{
		{"integer", `{"type":"integer"}`, true},
		{"string", `{"type":"string"}`, true},
		{"nonnullable union", `{"type":["integer","string"]}`, true},
		{"nullable union", `{"type":["integer","null"]}`, false},
		{"null type", `{"type":"null"}`, false},
		{"unconstrained", `{}`, false},
		{"boolean schema", `true`, false},
		{"nullable composition", `{"anyOf":[{"type":"string"},{"type":"null"}]}`, false},
		{"unresolved reference", `{"$ref":"#/$defs/nullable"}`, false},
	}
	for _, stream := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, tc.name), func(t *testing.T) {
				call := testCall(0, "a", "get_worker_trace", `{"intent_id": null}`)
				raw := string(complete([]wireCall{call}, "", "tool_calls"))
				if stream {
					raw = callsFrame(call) + terminal("tool_calls")
				}
				inner := roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(raw))}, nil
				})
				payload := fmt.Sprintf(`{"stream":%t,"tools":[{"type":"function","function":{"name":"get_worker_trace","parameters":{"type":"object","required":["intent_id"],"properties":{"intent_id":%s}}}}]}`, stream, tc.schema)
				req, err := http.NewRequest(http.MethodPost, "https://model.example/v1/chat/completions", strings.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := Wrap(inner).RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				out, err := io.ReadAll(resp.Body)
				if tc.reject {
					expectCode(t, err, "null_required_tool_argument")
					if stream {
						calls, _, _ := legacyCalls(t, string(out))
						if len(calls) != 0 {
							t.Fatal("null call escaped")
						}
					}
				} else if err != nil {
					t.Fatalf("valid required null rejected: %v", err)
				}
			})
		}
	}
}

func TestReviewAtomicIndexIsOptional(t *testing.T) {
	call := testCall(0, "a", "get_worker_trace", `{"intent_id":4}`)
	call.Index = nil
	raw := complete([]wireCall{call}, "", "tool_calls")
	out, err := normalizeComplete(raw, testRules)
	if err != nil || string(out) != string(raw) {
		t.Fatalf("atomic index incorrectly required: %s %v", out, err)
	}
}

func TestReviewVendorMetadataIsOpaque(t *testing.T) {
	raw := `data: {"choices":[{"delta":{"content":"ok","vendor":{"Choices":1,"choices":2,"CONTENT":3}},"finish_reason":"stop"}],"vendor":{"Tool_Calls":1,"tool_calls":2}}` + "\n\ndata: [DONE]\n\n"
	out, err := normalizeStream(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"Choices":1`) || !strings.Contains(out, `"Tool_Calls":1`) {
		t.Fatalf("vendor metadata lost: %s", out)
	}
}
