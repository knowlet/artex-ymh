package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	maxIntentArgumentBytes = 1 << 20
	maxIntentArgumentWraps = 4
)

// Only add_intent accepts this provider compatibility shape. Other tools may
// legitimately declare an arguments property; their inputs must stay untouched.
func normalizeIntentArguments(in json.RawMessage) (json.RawMessage, map[string]json.RawMessage, error) {
	if len(in) > maxIntentArgumentBytes {
		return nil, nil, fmt.Errorf("input exceeds %d bytes", maxIntentArgumentBytes)
	}
	for depth := 0; ; depth++ {
		in = bytes.TrimSpace(in)
		fields, err := intentArgumentObject(in)
		if err != nil {
			return nil, nil, err
		}
		inner, wrapped := fields["arguments"]
		if !wrapped {
			return in, fields, nil
		}
		if len(fields) != 1 {
			return nil, nil, fmt.Errorf("arguments wrapper cannot have sibling fields; pass summary or intents directly in one object")
		}
		if depth >= maxIntentArgumentWraps {
			return nil, nil, fmt.Errorf("arguments wrapper exceeds %d layers; pass summary or intents directly", maxIntentArgumentWraps)
		}
		inner = bytes.TrimSpace(inner)
		if len(inner) > 0 && inner[0] == '"' {
			var text string
			if err := json.Unmarshal(inner, &text); err != nil {
				return nil, nil, fmt.Errorf("arguments must contain a JSON object")
			}
			inner = json.RawMessage(text)
		}
		in = inner
	}
}

func intentArgumentObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("expected a JSON object containing summary or intents")
	}
	fields := make(map[string]json.RawMessage)
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid argument object")
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid argument object key")
		}
		// encoding/json matches struct fields case-insensitively. Reject aliases
		// too, rather than choosing one of two conflicting summaries/parents.
		folded := strings.ToLower(key)
		if folded == "arguments" && key != "arguments" {
			return nil, fmt.Errorf("arguments wrapper must use the exact lowercase field name")
		}
		if seen[folded] {
			return nil, fmt.Errorf("duplicate argument field %q", key)
		}
		seen[folded] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid argument object")
		}
		fields[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid argument object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after argument object")
	}
	return fields, nil
}

func parseIntentArguments(in json.RawMessage) ([]intentItem, bool, error) {
	in, fields, err := normalizeIntentArguments(in)
	if err != nil {
		return nil, false, err
	}
	var input struct {
		Intents []intentItem `json:"intents"`
		intentItem
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, false, err
	}
	if len(input.Intents) == 0 {
		return []intentItem{input.intentItem}, false, nil
	}
	for key := range fields {
		switch strings.ToLower(key) {
		case "summary", "asset_ids", "parent_ids", "priority", "chain_tags", "exploration":
			return nil, false, fmt.Errorf("batch field %q must be inside each intents item; top-level fields are not shared defaults", key)
		}
	}
	return input.Intents, true, nil
}
