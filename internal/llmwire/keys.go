package llmwire

import (
	"bytes"
	"encoding/json"
	"strings"
)

type wireLevel int

const (
	wireEnvelope wireLevel = iota
	wireChoice
	wireMessage
	wireTool
	wireFunction
)

var structuralKeys = [...][]string{
	wireEnvelope: {"choices", "error", "usage"},
	wireChoice:   {"index", "delta", "message", "finish_reason"},
	wireMessage:  {"role", "content", "refusal", "reasoning_content", "reasoning", "reasoning_text", "tool_calls"},
	wireTool:     {"index", "id", "type", "function"},
	wireFunction: {"name", "arguments"},
}

// validateWireKeys closes the map/struct decoding differential: our maps use
// exact keys, while Norma's encoding/json struct decoder matches ignoring case
// and merges some duplicate object fields. Inspect keys before a map loses
// duplicates. EqualFold also covers the Unicode folds accepted by Go's decoder.
// Only protocol objects are visited; argument strings and vendor metadata are
// data, not instructions, and must not be recursively canonicalized.
// The caller has already checked JSON syntax. Shape validation stays in the
// ordinary decoder so existing null/invalid-shape diagnostics remain unchanged.
func validateWireKeys(raw []byte, level wireLevel) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return protocolError("invalid_protocol_object")
	}
	seen := make(map[string]bool)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return protocolError("invalid_protocol_object")
		}
		key, ok := token.(string)
		if !ok {
			return protocolError("invalid_protocol_object")
		}
		known := false
		for _, canonical := range structuralKeys[level] {
			if strings.EqualFold(key, canonical) {
				if key != canonical {
					return protocolError("noncanonical_structural_key")
				}
				known = true
				break
			}
		}
		if known && seen[key] {
			return protocolError("duplicate_structural_key")
		}
		if known {
			seen[key] = true
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return protocolError("invalid_protocol_object")
		}
		var child wireLevel
		descend, array := false, false
		switch {
		case level == wireEnvelope && key == "choices":
			child, descend, array = wireChoice, true, true
		case level == wireChoice && (key == "delta" || key == "message"):
			child, descend = wireMessage, true
		case level == wireMessage && key == "tool_calls":
			child, descend, array = wireTool, true, true
		case level == wireTool && key == "function":
			child, descend = wireFunction, true
		}
		if !descend {
			continue
		}
		if array {
			var entries []json.RawMessage
			if json.Unmarshal(value, &entries) != nil {
				continue
			} // shape checked by caller
			for _, entry := range entries {
				if err := validateWireKeys(entry, child); err != nil {
					return err
				}
			}
		} else if err := validateWireKeys(value, child); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return protocolError("invalid_protocol_object")
	}
	return nil
}
