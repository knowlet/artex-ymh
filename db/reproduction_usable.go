package db

import (
	"encoding/json"
	"strings"
)

// reproductionUsable reports whether incoming JSON contains a meaningful recipe
// (entry point, prerequisite, or at least one step with request text).
func reproductionUsable(raw json.RawMessage) bool {
	if len(raw) < 3 {
		return false
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return false
	}
	if v, ok := root["entry_point"]; ok && jsonScalarNonempty(v) {
		return true
	}
	if v, ok := root["prerequisites"]; ok && jsonPrereqNonempty(v) {
		return true
	}
	steps, ok := root["steps"]
	if !ok {
		return false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(steps, &arr); err != nil {
		return false
	}
	for _, item := range arr {
		var step map[string]json.RawMessage
		if err := json.Unmarshal(item, &step); err != nil {
			continue
		}
		if req, ok := step["request"]; ok && jsonScalarNonempty(req) {
			return true
		}
	}
	return false
}

func jsonScalarNonempty(raw json.RawMessage) bool {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s) != ""
	}
	return false
}

func jsonPrereqNonempty(raw json.RawMessage) bool {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return jsonScalarNonempty(raw)
	}
	for _, item := range arr {
		if jsonScalarNonempty(item) {
			return true
		}
	}
	return false
}
