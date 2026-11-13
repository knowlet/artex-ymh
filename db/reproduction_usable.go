package db

import (
	"encoding/json"
	"strings"
)

// reproductionUsable reports whether incoming JSON contains a meaningful recipe
// (entry point or at least one step with request text).
func reproductionUsable(raw json.RawMessage) bool {
	if len(raw) < 3 {
		return false
	}
	var v struct {
		EntryPoint string `json:"entry_point"`
		Steps      []struct {
			Request string `json:"request"`
		} `json:"steps"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	if strings.TrimSpace(v.EntryPoint) != "" {
		return true
	}
	for _, st := range v.Steps {
		if strings.TrimSpace(st.Request) != "" {
			return true
		}
	}
	return false
}
