package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

// This narrow addendum also reaches installations with a stored planner body.
// It explains graph/tool semantics; it does not replace that body, broaden the
// role's tool bindings, or relax user-defined scope and operating restrictions.
const plannerAdaptiveGuidance = `

【基于证据调整规划】
以下是规划语义与可选策略，不覆盖用户明确规定的任务范围、操作约束、角色限制或审批要求；有冲突时服从那些限制。
- intent 的 done 只说明执行结束，不保证假设已证实、已排除或方法已穷尽。结合实际产物、最近 worker 反馈和工具错误判断：没有证据或工具失败不等于获得了否定证据。
- 现有路径没有推进时，指出仍未知但会改变下一步选择的问题，比较证据支持的不同方法。信息收集/验证本身可以成为合法意图；不需要先猜中漏洞。新方向必须有实质不同的问题、证据、目标或方法，不能只换措辞重复相同尝试。
- 仅按需发现当前角色获准的能力、读取有关的新证据；是否可直接探测仍取决于用户限制与角色权限。任务已有 fact 并不证明其他问题已解决；若本角色不能探测，可把具体问题交给获准的 worker。不得自行解锁未授权能力或绕过工具拒绝。
- 最近工具往返中的相同输入/相同结果只是重复观察，不算进展。重读旧 worker 前应能说明将查哪个尚未看过的步骤或为何结果可能已改变；工具调用失败应依据具体错误修正决策。对 add_intent 同时检查返回的 ids 和 errors，调用本身不代表派发成功。
- 可用 add_intent 的可选 exploration 记录 question、method、expected_signal、stop_condition；引用终态旧意图时用 prior_intent_ids 并说明 change。parent_ids 只用于可见的事实/发现，不能填旧 intent id。这些规划内容不是事实或目标证明。
- 推进仍以成功建立不重复意图或用真实证据证明目标为准；发现工具、读取材料、分析和失败的派发不会让进度检查自动通过。若合法路径被明确约束或缺少必要授权，说明具体阻碍，不编造工作。
`

const plannerAdaptiveRecoveryPrompt = `【规划进度校验：本轮唯一一次纠正／有界重新规划】
刚才尚未成功新增意图，也没有把未达成目标证明为 met。本次提供一次有界重新规划机会；没有固定工具步骤，也不要求原样重试。
先按下方刷新态势判断：若其他执行者已有 open/running 意图，或已无未达成目标，立即结束、不重复派发。否则结合最近工具往返与 worker 反馈，找出阻碍和仍未回答的决策问题，选择有实质差异、符合现有范围和操作约束的下一步。
可以按需发现当前角色获准的能力/技能、读取有关的新证据；直接目标探测必须已获角色和任务允许。若现有证据不足以选定验证方向，可提交带有可观察信号与停止条件的信息收集意图，由 worker 取得所缺证据。能力发现与取证是选择手段，不是固定前置步骤；不要耗尽预算重复读取相同参数下未变化的旧结果。
使用正常 add_intent 提交有根据且不重复的下一步；若真实证据已满足目标，使用 prove_goal。遇到拒绝或批量 errors，依据具体原因调整；不要绕过审批、扩大范围或编造意图。预算内仍无法合法推进时说明具体阻碍。之后仍检查实际落库结果，单纯分析、发现能力或失败的调用不算推进。
`

const (
	plannerExchangeLimit      = 8
	plannerPendingLimit       = 16
	plannerInputExcerptRunes  = 600
	plannerResultExcerptRunes = 1000
	plannerExcerptByteLimit   = 256 << 10
)

// plannerExchangeDigest keeps only bounded, redacted excerpts in memory for the
// one recovery input. Exact hashes use the FULL original input and result, so
// different IDs, queries, pages, and even truncated tails remain distinct. This
// is not the worker stuck detector (whose normalization intentionally removes
// numbers) and it does not invent or persist another model-generated summary.
type plannerExchangeDigest struct {
	pending      []plannerPendingExchange
	recent       []plannerToolExchange
	observations uint64
}

type plannerPendingExchange struct {
	idHash    [32]byte
	inputHash [32]byte
	tool      string
	toolUseID string
	input     string
}

type plannerToolExchange struct {
	Tool       string `json:"tool"`
	ToolUseID  string `json:"tool_use_id,omitempty"`
	Input      string `json:"input_excerpt,omitempty"`
	Result     string `json:"result_excerpt"`
	IsError    bool   `json:"is_error,omitempty"`
	BatchError bool   `json:"batch_errors,omitempty"`
	Repeated   int    `json:"same_input_result_observations"`
	key        [32]byte
}

func (d *plannerExchangeDigest) record(activity db.Activity) {
	switch activity.Kind {
	case "tool_use":
		d.pending = append(d.pending, plannerPendingExchange{
			idHash: sha256.Sum256([]byte(activity.ToolUseID)), inputHash: sha256.Sum256([]byte(activity.Detail)),
			tool: activity.Tool, toolUseID: plannerClip(activity.ToolUseID, 96),
			input: plannerEvidenceExcerpt(activity.Detail, plannerInputExcerptRunes, activity.Tool),
		})
		if len(d.pending) > plannerPendingLimit {
			d.pending = d.pending[1:]
		}
	case "tool_result":
		d.observations++
		idHash := sha256.Sum256([]byte(activity.ToolUseID))
		// Missing inputs can occur if an unusually large parallel batch exceeds
		// the window. Keep its result, but never merge unknown inputs by output.
		unknownInput := sha256.Sum256([]byte(fmt.Sprintf("unpaired:%s:%d", activity.ToolUseID, d.observations)))
		pending := plannerPendingExchange{idHash: idHash, inputHash: unknownInput, tool: activity.Tool, toolUseID: plannerClip(activity.ToolUseID, 96)}
		for i := len(d.pending) - 1; i >= 0; i-- {
			if activity.ToolUseID != "" && d.pending[i].idHash == idHash {
				pending = d.pending[i]
				d.pending = append(d.pending[:i], d.pending[i+1:]...)
				break
			}
		}
		resultHash := sha256.Sum256([]byte(activity.Detail))
		key := sha256.Sum256([]byte(fmt.Sprintf("%s:%x:%x:%t", pending.tool, pending.inputHash, resultHash, activity.IsError)))
		entry := plannerToolExchange{
			Tool: plannerClip(pending.tool, 160), ToolUseID: pending.toolUseID, Input: pending.input,
			Result:  plannerEvidenceExcerpt(activity.Detail, plannerResultExcerptRunes, pending.tool),
			IsError: activity.IsError, BatchError: plannerIntentBatchErrors(pending.tool, activity.Detail), Repeated: 1, key: key,
		}
		for i := range d.recent {
			if d.recent[i].key == key {
				entry.Repeated = min(d.recent[i].Repeated+1, 1_000_000)
				d.recent = append(d.recent[:i], d.recent[i+1:]...)
				break
			}
		}
		d.recent = append(d.recent, entry)
		if len(d.recent) > plannerExchangeLimit {
			d.recent = d.recent[1:]
		}
	}
}

func (d *plannerExchangeDigest) render() string {
	if len(d.recent) == 0 {
		return ""
	}
	data, _ := json.Marshal(d.recent)
	return "\n\n最近工具往返（有界窗口；次数仅统计窗口内完全相同的入参和结果；省略或脱敏不代表原文相同）：\n" + WrapUntrustedData("tool-output", string(data))
}

// add_intent intentionally returns ordinary JSON for mixed/fully rejected
// batches. The failure remains relevant even when the SDK's IsError is false.
func plannerIntentBatchErrors(tool, result string) bool {
	if tool != "add_intent" {
		return false
	}
	var batch struct {
		Errors any `json:"errors"`
	}
	if json.Unmarshal([]byte(result), &batch) != nil {
		return false
	}
	switch failures := batch.Errors.(type) {
	case map[string]any:
		return len(failures) > 0
	case []any:
		return len(failures) > 0
	default:
		return false
	}
}

var (
	plannerSecretHeader = regexp.MustCompile(`(?im)((?:proxy-)?authorization|(?:set-)?cookie|x-api-key)([ \t]*:[ \t]*)[^\r\n]*`)
	plannerSecretValue  = regexp.MustCompile(`(?i)(["']?(?:api[_-]?key|password|passwd|passphrase|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|token|authorization|cookie)["']?)(\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&,;]+)`)
	plannerURLUserinfo  = regexp.MustCompile(`(?i)(https?://)[^/\s@]*@`)
)

func plannerEvidenceExcerpt(raw string, limit int, tool string) string {
	if len(raw) > plannerExcerptByteLimit {
		return "(输出过大，摘录省略；需要时按具体 ID 或范围读取)"
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber() // int64 node IDs must not round through float64
	if json.Valid([]byte(raw)) && decoder.Decode(&value) == nil {
		value = plannerRedactValue(value, strings.Contains(strings.ToLower(tool), "credential"))
		if safe, err := json.Marshal(value); err == nil {
			raw = string(safe)
		}
	} else {
		raw = plannerRedactText(raw)
	}
	return plannerClip(raw, limit)
}

func plannerRedactValue(value any, credential bool) any {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(key))
			secret := false
			switch normalized {
			case "authorization", "proxyauthorization", "cookie", "setcookie", "password", "passwd", "passphrase", "secret", "clientsecret", "apikey", "xapikey", "token", "accesstoken", "refreshtoken", "privatekey", "credentialvalue":
				secret = true
			case "value":
				secret = credential
			}
			if secret {
				v[key] = "[redacted]"
			} else {
				v[key] = plannerRedactValue(child, credential)
			}
		}
	case []any:
		for i := range v {
			v[i] = plannerRedactValue(v[i], credential)
		}
	case string:
		return plannerRedactText(v)
	}
	return value
}

func plannerRedactText(text string) string {
	text = plannerSecretHeader.ReplaceAllString(text, "${1}${2}[redacted]")
	text = plannerSecretValue.ReplaceAllString(text, "${1}${2}[redacted]")
	return plannerURLUserinfo.ReplaceAllString(text, "${1}[redacted]@")
}

func plannerClip(text string, maxRunes int) string {
	if utf8.RuneCountInString(text) <= maxRunes {
		return text
	}
	return string([]rune(text)[:maxRunes]) + " …[truncated]"
}
