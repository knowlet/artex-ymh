package llmwire

import (
	"encoding/json"
	"fmt"
	"strconv"
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
	parsed, err := parseDSMLInvokes(inner)
	if err != nil {
		return "", "", nil, err
	}
	calls = make([]wireCall, 0, len(parsed))
	for i, inv := range parsed {
		raw, err := json.Marshal(inv.args)
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
	args map[string]any
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

func parseDSMLParameters(body string) (map[string]any, error) {
	args := map[string]any{}
	remaining := body
	for {
		start := strings.Index(remaining, dsmlParamOpen)
		if start < 0 {
			if strings.TrimSpace(remaining) != "" {
				return nil, protocolError("unparsed_dsml_tool_call")
			}
			break
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
		rawValue := strings.TrimSpace(remaining[:valEnd])
		remaining = remaining[valEnd+len(dsmlParamClose):]
		asString := dsmlAttrDefault(tag, "string", "false") == "true"
		value, err := coerceDSMLValue(rawValue, asString)
		if err != nil {
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

func coerceDSMLValue(raw string, asString bool) (any, error) {
	if asString {
		return raw, nil
	}
	if raw == "true" || raw == "false" {
		return raw == "true", nil
	}
	if raw == "null" {
		return nil, nil
	}
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return i, nil
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f, nil
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") || strings.HasPrefix(strings.TrimSpace(raw), "[") {
		var v any
		if json.Unmarshal([]byte(raw), &v) == nil {
			return v, nil
		}
	}
	return nil, fmt.Errorf("unparsed dsml value")
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
