// Package llmwire guards the Chat Completions wire boundary before Norma v0.4.3
// drops tool-call indices and replaces invalid argument JSON with {}.
// It does not interpret assistant prose as executable tool calls.
package llmwire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	maxBodyBytes = 16 << 20
	maxToolCalls = 128
	dsmlMarker   = "<｜DSML｜"
)

// ProtocolError is a non-retryable malformed model response. Do not include
// prompt text, arguments, or response bodies here: errors enter ordinary logs.
type ProtocolError struct{ Code string }

func (e *ProtocolError) Error() string { return "openai tool protocol: " + e.Code }
func protocolError(code string) error  { return &ProtocolError{Code: code} }

type toolSpec struct {
	Type     string `json:"type"`
	Function struct {
		Name       string        `json:"name"`
		Parameters argumentRules `json:"parameters"`
	} `json:"function"`
}

// argumentRules intentionally covers only required keys and their explicit
// top-level type's nullability, not arbitrary JSON Schema constraints.
type argumentRules struct {
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
}

type requestSpec struct {
	Stream bool       `json:"stream"`
	Tools  []toolSpec `json:"tools"`
}
type wireCall struct {
	Index    *int   `json:"index,omitempty"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}
type object = map[string]json.RawMessage

// Wrap must sit OUTSIDE the recording transport: the recorder must see the
// original provider bytes, not the normalized SSE that Norma consumes.
func Wrap(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base}
}

type transport struct{ base http.RoundTripper }

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/chat/completions") || req.GetBody == nil {
		return t.base.RoundTrip(req)
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	var spec requestSpec
	err = json.NewDecoder(body).Decode(&spec)
	_ = body.Close()
	if err != nil {
		return nil, fmt.Errorf("openai tool protocol: read request: %w", err)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || (resp.StatusCode < 200 || resp.StatusCode >= 300) || len(spec.Tools) == 0 {
		return resp, err
	}
	rules := make(map[string]argumentRules, len(spec.Tools))
	for _, tool := range spec.Tools {
		if tool.Type == "function" {
			rules[tool.Function.Name] = tool.Function.Parameters
		}
	}
	if len(rules) == 0 {
		return resp, nil
	}
	source := resp.Body
	if spec.Stream {
		resp.Body = newStreamBody(source, rules)
	} else {
		resp.Body = &completeBody{source: source, rules: rules}
	}
	// The normalized body can have a different length; do not leave stale framing.
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	return resp, nil
}

func validateCalls(calls []wireCall, rules map[string]argumentRules, finish string) error {
	if len(calls) == 0 {
		if finish == "tool_calls" {
			return protocolError("missing_tool_calls")
		}
		return nil
	}
	if len(calls) > maxToolCalls {
		return protocolError("too_many_tool_calls")
	}
	if finish != "tool_calls" && finish != "stop" {
		return protocolError("incomplete_tool_turn")
	}
	seen := make(map[string]bool, len(calls))
	for _, call := range calls {
		if call.ID == "" || len(call.ID) > 512 || seen[call.ID] {
			return protocolError("invalid_tool_id")
		}
		seen[call.ID] = true
		if call.Type != "function" {
			return protocolError("unsupported_tool_type")
		}
		rule, known := rules[call.Function.Name]
		if !known {
			return protocolError("undeclared_tool")
		}
		raw := strings.TrimSpace(call.Function.Arguments)
		// Empty is a legacy zero-argument call, never a substitute for broken JSON.
		if raw == "" && len(rule.Required) == 0 {
			raw = "{}"
		}
		var args map[string]json.RawMessage
		if !strings.HasPrefix(raw, "{") || json.Unmarshal([]byte(raw), &args) != nil || args == nil {
			return protocolError("invalid_tool_arguments")
		}
		for _, key := range rule.Required {
			value, ok := args[key]
			if !ok {
				return protocolError("missing_required_tool_argument")
			}
			// JSON Schema required means present, not non-null. Reject null
			// only when the property's explicit type excludes it; preserve
			// nullable unions and leave untyped/composed schemas to the tool.
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && forbidsNull(rule.Properties[key]) {
				return protocolError("null_required_tool_argument")
			}
		}
	}
	return nil
}

// forbidsNull only interprets an explicit, standard JSON Schema type. A
// missing type or a boolean/$ref/composed schema is outside this shim's scope.
func forbidsNull(raw json.RawMessage) bool {
	var schema struct {
		Type json.RawMessage `json:"type"`
	}
	if json.Unmarshal(raw, &schema) != nil || len(schema.Type) == 0 {
		return false
	}
	var single string
	var types []string
	if json.Unmarshal(schema.Type, &single) == nil {
		types = []string{single}
	} else if json.Unmarshal(schema.Type, &types) != nil {
		return false
	}
	if len(types) == 0 {
		return false
	}
	for _, typ := range types {
		switch typ {
		case "string", "integer", "number", "boolean", "object", "array":
		default:
			return false // includes null and unknown/nonstandard types
		}
	}
	return true
}

// normalizeComplete validates the whole atomic response before Norma can turn
// it into executable blocks. It deliberately does not unwrap arguments/input
// wrappers: they can be legitimate schema properties.
func normalizeComplete(raw []byte, rules map[string]argumentRules) ([]byte, error) {
	var envelope object
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, protocolError("invalid_response_json")
	}
	if err := validateWireKeys(raw, wireEnvelope); err != nil {
		return nil, err
	}
	if e := envelope["error"]; len(e) > 0 && string(e) != "null" {
		return raw, nil
	} // preserve SDK error handling
	var choices []struct {
		Message struct {
			Content   string     `json:"content"`
			ToolCalls []wireCall `json:"tool_calls"`
		} `json:"message"`
		Finish string `json:"finish_reason"`
	}
	if json.Unmarshal(envelope["choices"], &choices) != nil {
		return nil, protocolError("invalid_response_choices")
	}
	if len(choices) > 1 {
		return nil, protocolError("multiple_choices_unsupported")
	}
	for _, choice := range choices {
		if strings.Contains(choice.Message.Content, dsmlMarker) {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		if err := validateCalls(choice.Message.ToolCalls, rules, choice.Finish); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

type completeBody struct {
	source io.ReadCloser
	rules  map[string]argumentRules
	ready  bool
	reader *bytes.Reader
	err    error
}

func (b *completeBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !b.ready {
		b.ready = true
		raw, err := io.ReadAll(io.LimitReader(b.source, maxBodyBytes+1))
		if err == nil && len(raw) > maxBodyBytes {
			err = protocolError("response_too_large")
		}
		if err == nil {
			raw, err = normalizeComplete(raw, b.rules)
		}
		b.err = err
		b.reader = bytes.NewReader(raw)
	}
	if b.err != nil {
		return 0, b.err
	}
	return b.reader.Read(p)
}
func (b *completeBody) Close() error { return b.source.Close() }

// contentGuard retains only a possible marker suffix, so normal text remains
// streaming and a DSML marker split across arbitrary chunks never escapes.
// Reasoning and tool arguments are not passed through this guard.
type contentGuard struct{ tail string }

func (g *contentGuard) push(text string) (string, error) {
	text = g.tail + text
	g.tail = ""
	if strings.Contains(text, dsmlMarker) {
		return "", protocolError("unparsed_dsml_tool_call")
	}
	for n := min(len(text), len(dsmlMarker)-1); n > 0; n-- {
		if strings.HasSuffix(text, dsmlMarker[:n]) {
			g.tail = text[len(text)-n:]
			return text[:len(text)-n], nil
		}
	}
	return text, nil
}
func (g *contentGuard) finish() (string, error) {
	// Reject an unmistakable but truncated DSML token, not a normal trailing '<'.
	if strings.HasPrefix(g.tail, "<｜DSML") {
		return "", protocolError("unparsed_dsml_tool_call")
	}
	tail := g.tail
	g.tail = ""
	return tail, nil
}
