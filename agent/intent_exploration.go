package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

// intentExploration describes a model-chosen experiment, not a finding or a route
// selected by the scheduler. It travels with the intent across worker restarts.
type intentExploration struct {
	Question       string  `json:"question"`
	Method         string  `json:"method,omitempty"`
	ExpectedSignal string  `json:"expected_signal"`
	StopCondition  string  `json:"stop_condition"`
	PriorIntentIDs []int64 `json:"prior_intent_ids,omitempty"`
	Change         string  `json:"change,omitempty"`
}

const (
	explorationFieldRunes = 600
	explorationPriorCap   = 4
)

func intentExplorationSchema() map[string]any {
	text := func(description string) map[string]any {
		return map[string]any{"type": "string", "maxLength": explorationFieldRunes, "description": description}
	}
	return map[string]any{
		"type":        "object",
		"description": "可选：由模型选择的信息获取实验，不限工具或技术类别；这是待验证的计划，不是事实、发现、完成证明或额外授权。原有 summary/parent_ids 规则仍适用。",
		"properties": map[string]any{
			"question":        text("本次要消除的具体不确定性或待验证假设。"),
			"method":          text("拟用的方法或已配置能力；只是建议，worker 可在同一意图与授权范围内选择更合适的工具。"),
			"expected_signal": text("什么可观察结果能区分可能的解释；成功与否定结果都可产生信息。"),
			"stop_condition":  text("何时停止这一实验、写回已观察结果并交回 planner；不能扩大任务预算或越过任务约束。"),
			"prior_intent_ids": map[string]any{"type": "array", "maxItems": explorationPriorCap, "uniqueItems": true,
				"items":       map[string]any{"type": "integer", "minimum": 1},
				"description": "参考的已结束尝试（可选，最多4个，本任务或可见关联任务）；仅作比较，不是 parent_ids 证据锚点，也不恢复已停止工作。"},
			"change": text("参考旧尝试时必填：这次改变了哪个假设、证据、输入或方法，为什么能获得新信息；换工具名或换措辞本身不够。"),
		},
		"required":             []any{"question", "expected_signal", "stop_condition"},
		"additionalProperties": false,
	}
}

func (t *ToolSet) prepareIntentExploration(in *intentExploration) (*intentExploration, error) {
	if in == nil {
		return nil, nil
	}
	out := *in
	for _, field := range []struct {
		name     string
		value    *string
		required bool
	}{
		{"question", &out.Question, true}, {"method", &out.Method, false},
		{"expected_signal", &out.ExpectedSignal, true}, {"stop_condition", &out.StopCondition, true},
		{"change", &out.Change, false},
	} {
		*field.value = strings.TrimSpace(*field.value)
		if field.required && *field.value == "" {
			return nil, fmt.Errorf("exploration.%s 不能为空", field.name)
		}
		if !utf8.ValidString(*field.value) || utf8.RuneCountInString(*field.value) > explorationFieldRunes {
			return nil, fmt.Errorf("exploration.%s 必须是有效文本且不超过 %d 字符", field.name, explorationFieldRunes)
		}
	}
	if len(out.PriorIntentIDs) > explorationPriorCap {
		return nil, fmt.Errorf("exploration.prior_intent_ids 至多 %d 个", explorationPriorCap)
	}
	if len(out.PriorIntentIDs) > 0 && out.Change == "" {
		return nil, fmt.Errorf("exploration.change 必须说明本次与旧尝试的实质差异")
	}
	out.PriorIntentIDs = nil
	seen := map[int64]bool{}
	for _, id := range in.PriorIntentIDs {
		if id <= 0 || seen[id] {
			return nil, fmt.Errorf("exploration.prior_intent_ids 必须是互不重复的正整数")
		}
		seen[id] = true
		node, err := t.ts.GetNodeWithSources(id)
		if err != nil || node == nil || node.Kind != db.KindIntent {
			return nil, fmt.Errorf("exploration.prior_intent_ids 中 %d 不是当前可见的意图", id)
		}
		switch node.State {
		case "done", "exhausted", "blocked", "stopped":
		default:
			return nil, fmt.Errorf("exploration.prior_intent_ids 中 %d 尚未结束；不要重复派发正在执行或排队的尝试", id)
		}
		out.PriorIntentIDs = append(out.PriorIntentIDs, id)
	}
	return &out, nil
}

// Existing installations retain their edited tool schemas. Add only the new
// optional property at runtime; never reset descriptions, defaults or bindings.
func withIntentExplorationSchema(schema map[string]any) map[string]any {
	properties, _ := schema["properties"].(map[string]any)
	if _, exists := properties["exploration"]; exists {
		return schema
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		return schema
	}
	var copy map[string]any
	if json.Unmarshal(raw, &copy) != nil || copy == nil {
		return schema
	}
	properties, _ = copy["properties"].(map[string]any)
	if properties == nil {
		properties = map[string]any{}
		copy["properties"] = properties
	}
	properties["exploration"] = intentExplorationSchema()
	return copy
}

func compactIntentExploration(payload json.RawMessage) map[string]any {
	var p struct {
		Exploration *intentExploration `json:"exploration"`
	}
	if json.Unmarshal(payload, &p) != nil || p.Exploration == nil {
		return nil
	}
	clip := func(value string) string {
		runes := []rune(value)
		if len(runes) > 160 {
			return string(runes[:160]) + "…"
		}
		return value
	}
	e := p.Exploration
	out := map[string]any{"question": clip(e.Question), "expected_signal": clip(e.ExpectedSignal)}
	if e.Change != "" {
		out["change"] = clip(e.Change)
	}
	if len(e.PriorIntentIDs) > 0 {
		out["prior_intent_ids"] = e.PriorIntentIDs[:min(len(e.PriorIntentIDs), explorationPriorCap)]
	}
	return out
}
