// Package llmwire guards the Chat Completions wire boundary before Norma v0.4.3
// drops tool-call indices and replaces invalid argument JSON with {}.
// It does not interpret assistant prose as executable tool calls.
package llmwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/internal/toolargs"
)

// ErrUpstreamStreamInterrupted marks an upstream SSE error frame before the turn
// completed. It is attached to ProtocolError for transient retry classification.
var ErrUpstreamStreamInterrupted = errors.New("upstream stream interrupted")

// ErrStreamEndedWithoutFinish marks a clean socket close without finish_reason.
var ErrStreamEndedWithoutFinish = errors.New("stream ended without finish_reason")

const (
	maxBodyBytes = 16 << 20
	maxToolCalls = 128
	dsmlMarker   = "<｜DSML｜"
)

// ProtocolError is a malformed or incomplete model response at the wire boundary.
// Do not include prompt text, arguments, or response bodies here: errors enter
// ordinary logs. Some codes wrap ErrUpstreamStreamInterrupted or io.EOF so
// transient retry classifiers can recognize transport failures without treating
// malformed tool output as recoverable.
type ProtocolError struct {
	Code  string
	Cause error
}

func (e *ProtocolError) Error() string { return "openai tool protocol: " + e.Code }
func (e *ProtocolError) Unwrap() error { return e.Cause }

// Transient reports whether the failure is an upstream transport dropout that can
// recover on an unchanged replay. Malformed tool turns stay non-transient.
func (e *ProtocolError) Transient() bool {
	switch e.Code {
	case "upstream_stream_error", "missing_finish_reason":
		return true
	default:
		return false
	}
}

func protocolError(code string) error { return &ProtocolError{Code: code} }

func protocolTransientError(code string, cause error) error {
	return &ProtocolError{Code: code, Cause: cause}
}

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

func validateArgumentObject(args map[string]json.RawMessage, rule argumentRules) error {
	for _, key := range rule.Required {
		value, ok := args[key]
		if !ok {
			return protocolError("missing_required_tool_argument")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && forbidsNull(rule.Properties[key]) {
			return protocolError("null_required_tool_argument")
		}
	}
	return nil
}

func validateCalls(calls []wireCall, rules map[string]argumentRules, finish string) (bool, error) {
	if len(calls) == 0 {
		if finish == "tool_calls" {
			return false, protocolError("missing_tool_calls")
		}
		return false, nil
	}
	if len(calls) > maxToolCalls {
		return false, protocolError("too_many_tool_calls")
	}
	if finish != "tool_calls" && finish != "stop" {
		return false, protocolError("incomplete_tool_turn")
	}
	seen := make(map[string]bool, len(calls))
	rewrote := false
	for i := range calls {
		call := &calls[i]
		if call.ID == "" || len(call.ID) > 512 || seen[call.ID] {
			return false, protocolError("invalid_tool_id")
		}
		seen[call.ID] = true
		if call.Type != "function" {
			return false, protocolError("unsupported_tool_type")
		}
		rule, known := rules[call.Function.Name]
		if !known {
			return false, protocolError("undeclared_tool")
		}
		raw := strings.TrimSpace(call.Function.Arguments)
		if raw == "" && len(rule.Required) == 0 {
			raw = "{}"
		}
		var args map[string]json.RawMessage
		if !strings.HasPrefix(raw, "{") || json.Unmarshal([]byte(raw), &args) != nil || args == nil {
			return false, protocolError("invalid_tool_arguments")
		}
		if err := validateArgumentObject(args, rule); err != nil {
			inner, normErr := toolargs.NormalizeArguments(json.RawMessage(raw))
			if normErr != nil {
				return false, err
			}
			args = nil
			if json.Unmarshal(inner, &args) != nil || args == nil {
				return false, err
			}
			if err := validateArgumentObject(args, rule); err != nil {
				return false, err
			}
			call.Function.Arguments = string(bytes.TrimSpace(inner))
			rewrote = true
		}
	}
	return rewrote, nil
}

func marshalCallsIntoMessage(msg object, calls []wireCall) error {
	callsRaw, err := json.Marshal(calls)
	if err != nil {
		return protocolError("invalid_response_json")
	}
	msg["tool_calls"] = callsRaw
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
	var choices []json.RawMessage
	if json.Unmarshal(envelope["choices"], &choices) != nil {
		return nil, protocolError("invalid_response_choices")
	}
	if len(choices) > 1 {
		return nil, protocolError("multiple_choices_unsupported")
	}
	modified := false
	for i, choiceRaw := range choices {
		var choice object
		if json.Unmarshal(choiceRaw, &choice) != nil || choice == nil {
			return nil, protocolError("invalid_response_choices")
		}
		var finish string
		if raw := choice["finish_reason"]; len(raw) > 0 && string(raw) != "null" {
			_ = json.Unmarshal(raw, &finish)
		}
		var msg object
		if raw := choice["message"]; len(raw) > 0 && string(raw) != "null" {
			if json.Unmarshal(raw, &msg) != nil || msg == nil {
				return nil, protocolError("invalid_response_choices")
			}
		}
		if msg == nil {
			msg = object{}
		}
		var content string
		if raw := msg["content"]; len(raw) > 0 && string(raw) != "null" {
			_ = json.Unmarshal(raw, &content)
		}
		if raw := msg["refusal"]; len(raw) > 0 && string(raw) != "null" {
			var refusal string
			_ = json.Unmarshal(raw, &refusal)
			if strings.Contains(refusal, dsmlMarker) {
				return nil, protocolError("unparsed_dsml_tool_call")
			}
		}
		var existing []wireCall
		if raw := msg["tool_calls"]; len(raw) > 0 && string(raw) != "null" {
			if json.Unmarshal(raw, &existing) != nil {
				return nil, protocolError("invalid_response_choices")
			}
		}
		plain, calls, newFinish, promoted, err := promoteContentDSML(content, finish, existing)
		if err != nil {
			return nil, err
		}
		if !promoted {
			calls = existing
			newFinish = finish
		} else {
			msg["content"], _ = json.Marshal(plain)
			callsRaw, err := json.Marshal(calls)
			if err != nil {
				return nil, protocolError("invalid_response_json")
			}
			msg["tool_calls"] = callsRaw
			choice["finish_reason"], _ = json.Marshal(newFinish)
			msgRaw, err := json.Marshal(msg)
			if err != nil {
				return nil, protocolError("invalid_response_json")
			}
			choice["message"] = msgRaw
			choiceRaw, err := json.Marshal(choice)
			if err != nil {
				return nil, protocolError("invalid_response_json")
			}
			choices[i] = choiceRaw
			modified = true
		}
		rewrote, err := validateCalls(calls, rules, newFinish)
		if err != nil {
			return nil, err
		}
		if rewrote {
			if err := marshalCallsIntoMessage(msg, calls); err != nil {
				return nil, err
			}
			msgRaw, err := json.Marshal(msg)
			if err != nil {
				return nil, protocolError("invalid_response_json")
			}
			choice["message"] = msgRaw
			choiceRaw, err := json.Marshal(choice)
			if err != nil {
				return nil, protocolError("invalid_response_json")
			}
			choices[i] = choiceRaw
			modified = true
		}
	}
	if !modified {
		return raw, nil
	}
	envelope["choices"], _ = json.Marshal(choices)
	out, err := json.Marshal(envelope)
	if err != nil {
		return nil, protocolError("invalid_response_json")
	}
	return out, nil
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
// Complete DSML tool_calls blocks are held back and parsed at finish.
// Reasoning and tool arguments are not passed through this guard.
type contentGuard struct {
	tail      string
	heldPlain strings.Builder
	dsml      strings.Builder
	inDSML    bool
	parseDSML bool
}

func newDSMLContentGuard() contentGuard { return contentGuard{parseDSML: true} }

func newRefusalContentGuard() contentGuard { return contentGuard{parseDSML: false} }

func (g *contentGuard) push(text string) (string, error) {
	text = g.tail + text
	g.tail = ""
	if !g.parseDSML {
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
	if g.inDSML {
		if err := g.appendDSML(text); err != nil {
			return "", err
		}
		return "", nil
	}
	if idx := strings.Index(text, dsmlMarker); idx >= 0 {
		before := text[:idx]
		after := text[idx:]
		switch {
		case strings.HasPrefix(after, dsmlToolCallsOpen):
			g.inDSML = true
			if before != "" {
				g.heldPlain.WriteString(before)
			}
			if err := g.appendDSML(after); err != nil {
				return "", err
			}
			return "", nil
		case isDSMLToolCallsPrefix(after):
			g.tail = after
			if before != "" {
				g.heldPlain.WriteString(before)
			}
			return "", nil
		default:
			return "", protocolError("unparsed_dsml_tool_call")
		}
	}
	for n := min(len(text), len(dsmlMarker)-1); n > 0; n-- {
		if strings.HasSuffix(text, dsmlMarker[:n]) {
			g.tail = text[len(text)-n:]
			return text[:len(text)-n], nil
		}
	}
	if extra := possibleDSMLToolCallsTail(text); extra != "" {
		g.tail = extra
		return text[:len(text)-len(extra)], nil
	}
	return text, nil
}

func (g *contentGuard) appendDSML(text string) error {
	if g.dsml.Len()+len(text) > maxBodyBytes {
		return protocolError("unparsed_dsml_tool_call")
	}
	g.dsml.WriteString(text)
	return nil
}

func (g *contentGuard) finish() (string, []wireCall, error) {
	if !g.parseDSML {
		if strings.HasPrefix(g.tail, "<｜DSML") || isDSMLToolCallsPrefix(g.tail) {
			return "", nil, protocolError("unparsed_dsml_tool_call")
		}
		tail := g.tail
		g.tail = ""
		return tail, nil, nil
	}
	if g.inDSML || g.dsml.Len() > 0 {
		captured := g.dsml.String() + g.tail
		g.tail, g.inDSML = "", false
		g.dsml.Reset()
		prefix, suffix, calls, err := extractDSMLToolCalls(captured)
		if err != nil {
			return "", nil, err
		}
		outside := g.heldPlain.String() + prefix + suffix
		g.heldPlain.Reset()
		return outside, calls, nil
	}
	if strings.HasPrefix(g.tail, "<｜DSML") || isDSMLToolCallsPrefix(g.tail) {
		return "", nil, protocolError("unparsed_dsml_tool_call")
	}
	tail := g.tail
	g.tail = ""
	return tail, nil, nil
}

func isDSMLToolCallsPrefix(text string) bool {
	return text != "" && strings.HasPrefix(dsmlToolCallsOpen, text) && strings.HasPrefix(text, "<｜")
}

func possibleDSMLToolCallsTail(text string) string {
	for n := min(len(text), len(dsmlToolCallsOpen)-1); n > len(dsmlMarker); n-- {
		suffix := text[len(text)-n:]
		if strings.HasPrefix(dsmlToolCallsOpen, suffix) && !strings.HasPrefix(suffix, dsmlMarker) {
			return suffix
		}
		if strings.HasPrefix(suffix, dsmlMarker) && strings.HasPrefix(dsmlToolCallsOpen, suffix) {
			return suffix
		}
	}
	return ""
}
