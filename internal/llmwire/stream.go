package llmwire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
)

type pendingCall struct {
	id, typ         string
	name, arguments strings.Builder
}

// streamBody is pull-based: no reader goroutine, and Close immediately closes
// the underlying HTTP body. State belongs to one response, never a provider.
type streamBody struct {
	source    io.ReadCloser
	scanner   *bufio.Scanner
	rules     map[string]argumentRules
	calls     map[int]*pendingCall
	buffered  int
	content   contentGuard
	refusal   contentGuard
	finish    string
	sawFinish bool
	ended     bool
	pending   bytes.Buffer
	err       error
}

func newStreamBody(source io.ReadCloser, rules map[string]argumentRules) *streamBody {
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 4096), maxBodyBytes)
	body := &streamBody{source: source, scanner: scanner, rules: rules, calls: map[int]*pendingCall{}}
	body.content = newDSMLContentGuard()
	body.refusal = newRefusalContentGuard()
	return body
}
func (b *streamBody) Close() error { return b.source.Close() }
func (b *streamBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for b.pending.Len() == 0 && b.err == nil && !b.ended {
		data, err := b.nextFrame()
		if err == io.EOF {
			b.err = b.finalize()
			b.ended = true
			break
		}
		if err != nil {
			b.err = err
			break
		}
		if strings.TrimSpace(data) == "[DONE]" {
			b.err = b.finalize()
			b.ended = true
			break
		}
		b.err = b.frame(data)
	}
	// A failed frame may have queued text. Never deliver it with a failed turn.
	if b.err != nil {
		b.pending.Reset()
		return 0, b.err
	}
	if b.pending.Len() > 0 {
		return b.pending.Read(p)
	}
	return 0, io.EOF
}
func (b *streamBody) nextFrame() (string, error) {
	var data strings.Builder
	size := 0
	for b.scanner.Scan() {
		line := strings.TrimSuffix(b.scanner.Text(), "\r")
		size += len(line)
		if size > maxBodyBytes {
			return "", protocolError("sse_frame_too_large")
		}
		if line == "" {
			if data.Len() > 0 {
				return strings.TrimSuffix(data.String(), "\n"), nil
			}
			size = 0
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			data.WriteByte('\n')
		}
	}
	if err := b.scanner.Err(); err != nil {
		return "", err
	}
	if data.Len() > 0 {
		return strings.TrimSuffix(data.String(), "\n"), nil
	}
	return "", io.EOF
}
func (b *streamBody) emit(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b.pending.WriteString("data: ")
	b.pending.Write(raw)
	b.pending.WriteString("\n\n")
	return nil
}
func (b *streamBody) delta(v any, finish any) error {
	return b.emit(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": v, "finish_reason": finish}}})
}
func (b *streamBody) frame(data string) error {
	var envelope object
	if json.Unmarshal([]byte(data), &envelope) != nil || envelope == nil {
		return protocolError("invalid_sse_json")
	}
	if err := validateWireKeys([]byte(data), wireEnvelope); err != nil {
		return err
	}
	if e := envelope["error"]; len(e) > 0 && string(e) != "null" {
		if transientStreamError(e) {
			return protocolTransientError("upstream_stream_error", ErrUpstreamStreamInterrupted)
		}
		return protocolError("upstream_stream_error")
	}
	var choices []object
	if raw := envelope["choices"]; len(raw) > 0 && json.Unmarshal(raw, &choices) != nil {
		return protocolError("invalid_stream_choices")
	}
	if len(choices) > 1 {
		return protocolError("multiple_choices_unsupported")
	}
	if len(choices) == 0 {
		return b.emit(envelope)
	} // usage-only frames
	choice := choices[0]
	if choice == nil {
		return protocolError("invalid_stream_choice")
	}
	var index int
	if raw := choice["index"]; len(raw) > 0 {
		if json.Unmarshal(raw, &index) != nil || index != 0 {
			return protocolError("invalid_choice_index")
		}
	}
	var delta object
	if raw := choice["delta"]; len(raw) > 0 && string(raw) != "null" {
		if json.Unmarshal(raw, &delta) != nil {
			return protocolError("invalid_stream_delta")
		}
	}
	if delta == nil {
		delta = object{}
	}
	var finish string
	if raw := choice["finish_reason"]; len(raw) > 0 && string(raw) != "null" {
		if json.Unmarshal(raw, &finish) != nil {
			return protocolError("invalid_finish_reason")
		}
	}
	if b.sawFinish && (len(delta) != 0 || finish != "") {
		return protocolError("data_after_finish")
	}
	if raw := delta["tool_calls"]; len(raw) > 0 && string(raw) != "null" {
		var calls []wireCall
		if json.Unmarshal(raw, &calls) != nil {
			return protocolError("invalid_tool_delta")
		}
		for _, call := range calls {
			if err := b.addCall(call); err != nil {
				return err
			}
		}
		delete(delta, "tool_calls")
	}
	if raw := delta["content"]; len(raw) > 0 && string(raw) != "null" {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return protocolError("invalid_content_delta")
		}
		text, err := b.content.push(text)
		if err != nil {
			return err
		}
		if text == "" {
			delete(delta, "content")
		} else {
			delta["content"], _ = json.Marshal(text)
		}
	}
	if raw := delta["refusal"]; len(raw) > 0 && string(raw) != "null" {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return protocolError("invalid_refusal_delta")
		}
		text, err := b.refusal.push(text)
		if err != nil {
			return err
		}
		if text == "" {
			delete(delta, "refusal")
		} else {
			delta["refusal"], _ = json.Marshal(text)
		}
	}
	if finish != "" {
		b.finish, b.sawFinish = finish, true
	}
	choice["delta"], _ = json.Marshal(delta)
	choice["finish_reason"] = json.RawMessage("null")
	envelope["choices"], _ = json.Marshal(choices)
	// Reasoning, usage and vendor metadata pass through unchanged.
	return b.emit(envelope)
}
func (b *streamBody) addCall(call wireCall) error {
	if call.Index == nil {
		return protocolError("missing_tool_index")
	}
	index := *call.Index
	if index < 0 || index >= maxToolCalls {
		return protocolError("invalid_tool_index")
	}
	b.buffered += len(call.ID) + len(call.Type) + len(call.Function.Name) + len(call.Function.Arguments)
	if b.buffered > maxBodyBytes {
		return protocolError("tool_arguments_too_large")
	}
	p := b.calls[index]
	if p == nil {
		p = &pendingCall{}
		b.calls[index] = p
	}
	if call.ID != "" {
		if p.id != "" && p.id != call.ID {
			return protocolError("conflicting_tool_id")
		}
		p.id = call.ID
	}
	if call.Type != "" {
		if p.typ != "" && p.typ != call.Type {
			return protocolError("conflicting_tool_type")
		}
		p.typ = call.Type
	}
	p.name.WriteString(call.Function.Name)
	p.arguments.WriteString(call.Function.Arguments)
	if len(p.id) > 512 || p.name.Len() > 512 {
		return protocolError("tool_identity_too_large")
	}
	return nil
}
func (b *streamBody) finalize() error {
	// A clean socket EOF is not a completed model turn. In particular, never
	// release even syntactically valid tool arguments without a terminal frame.
	if !b.sawFinish {
		_, contentCalls, contentErr := b.content.finish()
		_, refusalCalls, refusalErr := b.refusal.finish()
		// No tool frame can be released without a finish marker. A truncated
		// tool turn stays a permanent protocol failure; a text-only premature
		// EOF retains transport classification for the caller's safe retry gate.
		if len(b.calls) == 0 && len(contentCalls) == 0 && len(refusalCalls) == 0 && contentErr == nil && refusalErr == nil {
			return protocolTransientError("missing_finish_reason", ErrStreamEndedWithoutFinish)
		}
		return protocolError("missing_finish_reason")
	}
	indices := make([]int, 0, len(b.calls))
	for index := range b.calls {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	calls := make([]wireCall, 0, len(indices))
	for _, index := range indices {
		p := b.calls[index]
		call := wireCall{Index: &index, ID: p.id, Type: p.typ}
		call.Function.Name, call.Function.Arguments = p.name.String(), p.arguments.String()
		calls = append(calls, call)
	}
	finish := b.finish
	tail, dsmlContent, err := b.content.finish()
	if err != nil {
		return err
	}
	refusalTail, _, err := b.refusal.finish()
	if err != nil {
		return err
	}
	if refusalTail != "" && strings.Contains(refusalTail, dsmlMarker) {
		return protocolError("unparsed_dsml_tool_call")
	}
	hadStructured := len(calls) > 0
	if len(dsmlContent) > 0 {
		if hadStructured || !shouldPromoteContentDSML(finish, tail) {
			return protocolError("unparsed_dsml_tool_call")
		}
		calls = appendParsedDSMLCalls(calls, dsmlContent)
		if finish == "stop" || finish == "" {
			finish = "tool_calls"
		}
	}
	if _, err := validateCalls(calls, b.rules, finish); err != nil {
		return err
	}
	if tail != "" {
		if err := b.delta(map[string]string{"content": tail}, nil); err != nil {
			return err
		}
	}
	if refusalTail != "" {
		if err := b.delta(map[string]string{"refusal": refusalTail}, nil); err != nil {
			return err
		}
	}
	// Emit each complete call contiguously. Norma's unindexed accumulator now
	// receives start(A),args(A),start(B),args(B), never interleaved arguments.
	if len(calls) > 0 {
		if err := b.delta(map[string]any{"tool_calls": calls}, nil); err != nil {
			return err
		}
	}
	if err := b.delta(map[string]any{}, finish); err != nil {
		return err
	}
	b.pending.WriteString("data: [DONE]\n\n")
	return nil
}

func transientStreamError(raw json.RawMessage) bool {
	var e struct{ Type, Code string }
	if json.Unmarshal(raw, &e) != nil {
		return false
	}
	for _, value := range []string{e.Type, e.Code} {
		switch strings.ToLower(value) {
		case "insufficient_quota", "quota_exceeded", "authentication_error", "invalid_api_key", "permission_error", "invalid_request_error", "context_length_exceeded":
			return false
		}
	}
	for _, value := range []string{e.Type, e.Code} {
		switch strings.ToLower(value) {
		case "overloaded_error", "server_error", "api_error", "internal_server_error", "rate_limit_error", "rate_limit_exceeded":
			return true
		}
	}
	return false
}
