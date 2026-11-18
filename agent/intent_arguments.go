package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/internal/toolargs"
)

// Only add_intent accepts this provider compatibility shape. Other tools may
// legitimately declare an arguments property; their inputs must stay untouched.
func normalizeIntentArguments(in json.RawMessage) (json.RawMessage, map[string]json.RawMessage, error) {
	return toolargs.NormalizeArgumentsEnvelope(in)
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
