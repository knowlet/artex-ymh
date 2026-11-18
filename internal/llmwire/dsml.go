package llmwire

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const dsmlToolCallsOpen = dsmlMarker + "tool_calls"

// LeakedDSMLBatchFixture is the production-shaped multi-invoke DSML block that
// previously leaked into assistant content instead of executing as tool calls.
const LeakedDSMLBatchFixture = `<｜DSML｜tool_calls
<｜DSML｜invoke name="get_worker_output"> <｜DSML｜parameter name="intent_id" string="false">8</｜DSML｜parameter> </｜DSML｜invoke> <｜DSML｜invoke name="get_worker_output"> <｜DSML｜parameter name="intent_id" string="false">9</｜DSML｜parameter> </｜DSML｜invoke> <｜DSML｜invoke name="get_worker_output"> <｜DSML｜parameter name="intent_id" string="false">10</｜DSML｜parameter> </｜DSML｜invoke> <｜DSML｜invoke name="get_worker_output"> <｜DSML｜parameter name="intent_id" string="false">11</｜DSML｜parameter> </｜DSML｜invoke> </｜DSML｜tool_calls>`

var (
	dsmlSuffix         = strings.TrimPrefix(dsmlMarker, "<")
	dsmlToolCallsClose = "</" + dsmlSuffix + "tool_calls>"
	dsmlInvokeOpen     = dsmlMarker + "invoke"
	dsmlInvokeClose    = "</" + dsmlSuffix + "invoke>"
	dsmlParamOpen      = dsmlMarker + "parameter"
	dsmlParamClose     = "</" + dsmlSuffix + "parameter>"
)

// extractDSMLToolCalls finds one complete DSML tool_calls block in text and
// converts it into wire calls. Plain text before/after the block is returned
// separately. When a tool_calls block is present but malformed, err is set.
func extractDSMLToolCalls(text string) (prefix, suffix string, calls []wireCall, err error) {
	start := strings.Index(text, dsmlToolCallsOpen)
	if start < 0 {
		return text, "", nil, nil
	}
	prefix = text[:start]
	rest := text[start+len(dsmlToolCallsOpen):]
	end := strings.Index(rest, dsmlToolCallsClose)
	if end < 0 {
		return "", "", nil, protocolError("unparsed_dsml_tool_call")
	}
	inner := rest[:end]
	suffix = rest[end+len(dsmlToolCallsClose):]
	if strings.Contains(prefix, dsmlMarker) || strings.Contains(suffix, dsmlMarker) {
		return "", "", nil, protocolError("unparsed_dsml_tool_call")
	}
	inner = strings.TrimSpace(inner)
	if strings.HasPrefix(inner, ">") {
		inner = strings.TrimSpace(inner[1:])
	}
	if strings.TrimSpace(inner) != "" && strings.Index(inner, dsmlInvokeOpen) > 0 {
		if junk := strings.TrimSpace(inner[:strings.Index(inner, dsmlInvokeOpen)]); junk != "" {
			return "", "", nil, protocolError("unparsed_dsml_tool_call")
		}
	}
	parsed, err := parseDSMLInvokes(inner)
	if err != nil {
		return "", "", nil, err
	}
	calls = make([]wireCall, 0, len(parsed))
	for i, inv := range parsed {
		raw, err := marshalDSMLArgs(inv.args)
		if err != nil {
			return "", "", nil, protocolError("unparsed_dsml_tool_call")
		}
		idx := i
		call := wireCall{Index: &idx, ID: fmt.Sprintf("dsml_%d", i), Type: "function"}
		call.Function.Name = inv.name
		call.Function.Arguments = string(raw)
		calls = append(calls, call)
	}
	return prefix, suffix, calls, nil
}

type dsmlInvoke struct {
	name string
	args map[string]json.RawMessage
}

func parseDSMLInvokes(inner string) ([]dsmlInvoke, error) {
	var out []dsmlInvoke
	remaining := inner
	for {
		start := strings.Index(remaining, dsmlInvokeOpen)
		if start < 0 {
			if strings.TrimSpace(remaining) != "" {
				return nil, protocolError("unparsed_dsml_tool_call")
			}
			break
		}
		if start > 0 && strings.TrimSpace(remaining[:start]) != "" {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		remaining = remaining[start+len(dsmlInvokeOpen):]
		closeIdx := strings.Index(remaining, ">")
		if closeIdx < 0 {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		tag := remaining[:closeIdx]
		remaining = remaining[closeIdx+1:]
		name, ok := dsmlAttr(tag, "name")
		if !ok || name == "" {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		bodyEnd := strings.Index(remaining, dsmlInvokeClose)
		if bodyEnd < 0 {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		body := remaining[:bodyEnd]
		remaining = remaining[bodyEnd+len(dsmlInvokeClose):]
		args, err := parseDSMLParameters(body)
		if err != nil {
			return nil, err
		}
		out = append(out, dsmlInvoke{name: name, args: args})
	}
	if len(out) == 0 {
		return nil, protocolError("unparsed_dsml_tool_call")
	}
	return out, nil
}

func parseDSMLParameters(body string) (map[string]json.RawMessage, error) {
	args := map[string]json.RawMessage{}
	remaining := body
	for {
		start := strings.Index(remaining, dsmlParamOpen)
		if start < 0 {
			if strings.TrimSpace(remaining) != "" {
				return nil, protocolError("unparsed_dsml_tool_call")
			}
			break
		}
		if start > 0 && strings.TrimSpace(remaining[:start]) != "" {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		remaining = remaining[start+len(dsmlParamOpen):]
		closeIdx := strings.Index(remaining, ">")
		if closeIdx < 0 {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		tag := remaining[:closeIdx]
		remaining = remaining[closeIdx+1:]
		name, ok := dsmlAttr(tag, "name")
		if !ok || name == "" {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		valEnd := strings.Index(remaining, dsmlParamClose)
		if valEnd < 0 {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		rawValue := remaining[:valEnd]
		remaining = remaining[valEnd+len(dsmlParamClose):]
		asString := dsmlAttrDefault(tag, "string", "false") == "true"
		value, err := coerceDSMLValue(rawValue, asString)
		if err != nil {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		if _, exists := args[name]; exists {
			return nil, protocolError("unparsed_dsml_tool_call")
		}
		args[name] = value
	}
	return args, nil
}

func dsmlAttr(tag, key string) (string, bool) {
	needle := key + `="`
	i := strings.Index(tag, needle)
	if i < 0 {
		return "", false
	}
	rest := tag[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

func dsmlAttrDefault(tag, key, fallback string) string {
	v, ok := dsmlAttr(tag, key)
	if !ok {
		return fallback
	}
	return v
}

func coerceDSMLValue(raw string, asString bool) (json.RawMessage, error) {
	if asString {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(encoded), nil
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("unparsed dsml value")
	}
	switch trimmed {
	case "true":
		return json.RawMessage("true"), nil
	case "false":
		return json.RawMessage("false"), nil
	case "null":
		return json.RawMessage("null"), nil
	}
	num := json.Number(trimmed)
	if _, err := num.Int64(); err == nil {
		return json.RawMessage(trimmed), nil
	}
	if _, err := num.Float64(); err == nil {
		return json.RawMessage(trimmed), nil
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if !json.Valid([]byte(trimmed)) {
			return nil, fmt.Errorf("unparsed dsml value")
		}
		return json.RawMessage(trimmed), nil
	}
	return nil, fmt.Errorf("unparsed dsml value")
}

func marshalDSMLArgs(args map[string]json.RawMessage) ([]byte, error) {
	if len(args) == 0 {
		return []byte("{}"), nil
	}
	var buf strings.Builder
	buf.WriteByte('{')
	first := true
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(args[k])
	}
	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

// shouldPromoteContentDSML limits DSML→tool promotion to provider tool turns, not
// quoted envelopes embedded in ordinary assistant prose (finish=stop with non-DSML text).
func shouldPromoteContentDSML(finish, outsideText string) bool {
	if finish == "tool_calls" {
		return true
	}
	if finish != "stop" && finish != "" {
		return false
	}
	return strings.TrimSpace(outsideText) == ""
}

func promoteContentDSML(content string, finish string, existing []wireCall) (plain string, calls []wireCall, newFinish string, promoted bool, err error) {
	if !strings.Contains(content, dsmlMarker) {
		return content, existing, finish, false, nil
	}
	if !strings.Contains(content, dsmlToolCallsOpen) {
		return "", nil, finish, false, protocolError("unparsed_dsml_tool_call")
	}
	prefix, suffix, parsed, err := extractDSMLToolCalls(content)
	if err != nil {
		return "", nil, finish, false, err
	}
	if len(parsed) == 0 {
		return "", nil, finish, false, protocolError("unparsed_dsml_tool_call")
	}
	if len(existing) > 0 {
		return "", nil, finish, false, protocolError("unparsed_dsml_tool_call")
	}
	outside := prefix + suffix
	if !shouldPromoteContentDSML(finish, outside) {
		return "", nil, finish, false, protocolError("unparsed_dsml_tool_call")
	}
	newFinish = finish
	if finish == "stop" || finish == "" {
		newFinish = "tool_calls"
	}
	return outside, parsed, newFinish, true, nil
}

func appendParsedDSMLCalls(existing, parsed []wireCall) []wireCall {
	if len(parsed) == 0 {
		return existing
	}
	if len(existing) > 0 {
		return existing
	}
	out := make([]wireCall, len(parsed))
	copy(out, parsed)
	return out
}
