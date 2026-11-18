// Package toolargs normalizes provider-specific argument envelopes before domain
// handlers or wire-level required-field checks run.
package toolargs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	MaxArgumentBytes = 1 << 20
	MaxArgumentWraps = 4
)

// NormalizeArgumentsEnvelope unwraps up to MaxArgumentWraps single-property
// {"arguments": ...} layers. A layer may hold a JSON object or a JSON-encoded
// object string. Returns the inner object plus its top-level fields.
func NormalizeArgumentsEnvelope(in json.RawMessage) (json.RawMessage, map[string]json.RawMessage, error) {
	if len(in) > MaxArgumentBytes {
		return nil, nil, fmt.Errorf("input exceeds %d bytes", MaxArgumentBytes)
	}
	for depth := 0; ; depth++ {
		in = bytes.TrimSpace(in)
		fields, err := argumentObject(in)
		if err != nil {
			return nil, nil, err
		}
		inner, wrapped := fields["arguments"]
		if !wrapped {
			return in, fields, nil
		}
		if len(fields) != 1 {
			return nil, nil, fmt.Errorf("arguments wrapper cannot have sibling fields; pass tool fields directly in one object")
		}
		if depth >= MaxArgumentWraps {
			return nil, nil, fmt.Errorf("arguments wrapper exceeds %d layers; pass tool fields directly", MaxArgumentWraps)
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

// NormalizeArguments is like NormalizeArgumentsEnvelope but omits the field map.
func NormalizeArguments(in json.RawMessage) (json.RawMessage, error) {
	out, _, err := NormalizeArgumentsEnvelope(in)
	return out, err
}

func argumentObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("expected a JSON object")
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
