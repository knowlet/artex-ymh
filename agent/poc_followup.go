package agent

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// plannerPOCFollowupEnabled gates deterministic PoC-followup hints in graph_overview
// and the planner wake-up prompt. Default on; set ARTEX_PLANNER_POC_FOLLOWUP=0|false
// to disable without affecting worker evidence rules.
func plannerPOCFollowupEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_PLANNER_POC_FOLLOWUP"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

type accessSignal struct {
	kind     string
	patterns []string
}

// accessVulnSignals are positive access/privilege patterns (substring match, lowercased text).
// Negative conclusions are filtered earlier via isNegativeConclusion.
var accessVulnSignals = []accessSignal{
	{kind: "session_access", patterns: []string{
		"合法会话", "有效会话", "valid session", "authenticated session", "logged in as",
		"登录成功", "login successful", "login success", "session cookie", "session token",
		"set-cookie", "bearer token", "jwt ", "jwt:", "access token", "refresh token",
		"已认证", "authenticated as", "obtained session", "获取session", "获得session",
	}},
	{kind: "shell_rce", patterns: []string{
		"交互式 shell", "interactive shell", "reverse shell", "webshell", "web shell",
		"command execution", "命令执行", "rce", "remote code", "代码执行", "got shell",
		"shell access", "cmd.exe", "/bin/sh", "whoami",
	}},
	{kind: "privilege_gain", patterns: []string{
		"提权", "privilege escalation", "管理员权限", "admin access", "root access",
		"domain admin", "system authority", "sudo ", "nt authority", "高权限",
	}},
	{kind: "sensitive_access", patterns: []string{
		"敏感数据", "sensitive data", "未授权访问", "unauthorized access", "越权",
		"idor", "任意用户", "任意文件", "任意读取", "download unauthorized", "数据泄露",
		"database dump", "凭据", "credential", "password hash", "api key obtained",
	}},
}

// accessVulnCandidateFact reports whether an exploration fact is strong enough to
// warrant a follow-up PoC verification intent. It never upgrades findings itself.
func accessVulnCandidateFact(summary, detail, confidence string) (ok bool, kind string) {
	text := strings.ToLower(summary + "\n" + detail)
	if isNegativeConclusion(summary + "\n" + detail) {
		return false, ""
	}
	for _, sig := range accessVulnSignals {
		for _, p := range sig.patterns {
			if strings.Contains(text, strings.ToLower(p)) {
				kind = sig.kind
				ok = true
				break
			}
		}
		if ok {
			break
		}
	}
	if !ok {
		return false, ""
	}
	conf := normalizeFactConfidence(confidence)
	if conf == FactConfidenceInferred {
		// Inferred positives are easy to false-alarm; only follow up on the strongest kinds.
		switch kind {
		case "shell_rce", "privilege_gain":
		default:
			return false, ""
		}
	}
	return true, kind
}

func factPayloadFields(n *db.Node) (summary, detail, confidence string) {
	if n == nil {
		return "", "", ""
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) != nil {
		return "", "", ""
	}
	summary, _ = p["summary"].(string)
	detail, _ = p["detail"].(string)
	confidence, _ = p["confidence"].(string)
	return summary, detail, confidence
}

var pocVerificationIntentPatterns = []string{
	"poc", "复现", "验证漏洞", "漏洞验证", "证明可利用", "可复现", "exploit", "漏洞利用",
	"confirm vuln", "verify vuln", "prove exploit", "demonstrate", "weaponize",
}

// intentLooksLikePOCVerification heuristically detects intents whose job is to obtain PoC.
func intentLooksLikePOCVerification(summary string, exploration map[string]any) bool {
	s := strings.ToLower(summary)
	for _, p := range pocVerificationIntentPatterns {
		if strings.Contains(s, strings.ToLower(p)) {
			return true
		}
	}
	if exploration == nil {
		return false
	}
	for _, key := range []string{"question", "method", "expected_signal", "stop_condition"} {
		if v, ok := exploration[key].(string); ok && strings.TrimSpace(v) != "" {
			vs := strings.ToLower(v)
			for _, p := range pocVerificationIntentPatterns {
				if strings.Contains(vs, strings.ToLower(p)) {
					return true
				}
			}
		}
	}
	return false
}

func parentSet(parentsOf map[int64][]int64, intentID int64) map[int64]bool {
	out := map[int64]bool{}
	for _, id := range parentsOf[intentID] {
		out[id] = true
	}
	return out
}

func intentCoversPOCFact(openRunning []*db.Node, parentsOf map[int64][]int64, factID int64) bool {
	for _, n := range openRunning {
		if n.Kind != db.KindIntent {
			continue
		}
		for _, pid := range parentsOf[n.ID] {
			if pid == factID {
				return true
			}
		}
	}
	return false
}

func intentYieldsFinding(yieldsOf map[int64][]int64, kindByID map[int64]string, intentID int64) bool {
	for _, yid := range yieldsOf[intentID] {
		if kindByID[yid] == db.KindFinding {
			return true
		}
	}
	return false
}

func blockedReasonModelRecoverable(reason string) bool {
	if strings.TrimSpace(reason) == "" {
		return true
	}
	if reason == db.IntentBlockedLLMQuota {
		return false
	}
	r := strings.ToLower(reason)
	for _, frag := range []string{"model", "llm", "timeout", "504", "gateway", "rate", "overload", "transient", "provider"} {
		if strings.Contains(r, frag) {
			return true
		}
	}
	return false
}

type pocFollowupSnapshot struct {
	Candidates     []map[string]any
	BlockedRetries []map[string]any
}

// plannerPOCFollowupRules is a static planner addendum; per-round candidates live in graph_overview.
const plannerPOCFollowupRules = `

【枚举→漏洞验证链】graph_overview 的 poc_verification_candidates 列出 access/session 等事实支撑的验证候选；needs_followup=true 时必须 add_intent 派 worker 索取可复现 PoC（parent_ids 绑定 fact_id），不得以 record_fact 代替 report_finding 收官。blocked_poc_retries 覆盖模型故障后仍可规划的验证意图；永久 llm_quota_exhausted 除外。worker 侧 report_finding 门槛不变。`

func buildPOCFollowupSnapshot(
	factNodes, findingNodes, allIntents []*db.Node,
	parentsOf, yieldsOf map[int64][]int64,
	factFrom map[int64]int64,
	openRunning []*db.Node,
) pocFollowupSnapshot {
	kindByID := map[int64]string{}
	for _, n := range factNodes {
		kindByID[n.ID] = db.KindFact
	}
	for _, n := range findingNodes {
		kindByID[n.ID] = db.KindFinding
	}
	var out pocFollowupSnapshot
	for _, n := range factNodes {
		sum, det, conf := factPayloadFields(n)
		ok, kind := accessVulnCandidateFact(sum, det, conf)
		if !ok {
			continue
		}
		fromIntent := factFrom[n.ID]
		if fromIntent > 0 && intentYieldsFinding(yieldsOf, kindByID, fromIntent) {
			continue
		}
		covered := intentCoversPOCFact(openRunning, parentsOf, n.ID)
		item := map[string]any{
			"fact_id": n.ID, "kind": kind, "summary": sum, "needs_followup": !covered,
		}
		if fromIntent > 0 {
			item["from_intent"] = fromIntent
		}
		if covered {
			item["covered_by"] = "open_or_running_intent_with_parent"
		} else {
			item["planner_action"] = "add_intent: parent_ids=[fact_id], worker obtains reproducible PoC; record_fact alone does not close the chain"
		}
		out.Candidates = append(out.Candidates, item)
	}
	for _, n := range allIntents {
		if n.State != "blocked" {
			continue
		}
		if !blockedReasonModelRecoverable(n.BlockedReason) {
			continue
		}
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		summary, _ := p["summary"].(string)
		exp := compactIntentExploration(n.Payload)
		looksVerify := intentLooksLikePOCVerification(summary, exp)
		parents := parentsOf[n.ID]
		var parentFacts []int64
		supportsAccess := looksVerify
		for _, pid := range parents {
			if fn := nodeByID(factNodes, pid); fn != nil {
				s, d, c := factPayloadFields(fn)
				if ok, _ := accessVulnCandidateFact(s, d, c); ok {
					supportsAccess = true
					parentFacts = append(parentFacts, pid)
				}
			}
		}
		for _, yid := range yieldsOf[n.ID] {
			if fn := nodeByID(factNodes, yid); fn != nil {
				s, d, c := factPayloadFields(fn)
				if ok, _ := accessVulnCandidateFact(s, d, c); ok {
					supportsAccess = true
					parentFacts = append(parentFacts, yid)
				}
			}
		}
		if !supportsAccess {
			continue
		}
		covered := false
		for _, fid := range parentFacts {
			if intentCoversPOCFact(openRunning, parentsOf, fid) {
				covered = true
				break
			}
		}
		if !covered && looksVerify {
			for _, fid := range parentFacts {
				if intentCoversPOCFact(openRunning, parentsOf, fid) {
					covered = true
					break
				}
			}
		}
		retry := map[string]any{
			"intent_id": n.ID, "summary": summary, "needs_followup": !covered,
			"model_retry_exhausted": n.ModelRetryCount > 0,
		}
		if n.BlockedReason != "" {
			retry["blocked_reason"] = n.BlockedReason
		}
		if len(parentFacts) > 0 {
			retry["access_fact_ids"] = parentFacts
		}
		if !covered {
			retry["planner_action"] = "dispatch NEW PoC verification add_intent (parent_ids on access facts; prior_intent_ids+change if continuing blocked work); model_retry may reopen the same intent when scheduled—do not duplicate blindly"
		}
		out.BlockedRetries = append(out.BlockedRetries, retry)
	}
	return out
}

func nodeByID(nodes []*db.Node, id int64) *db.Node {
	for _, n := range nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

// renderPOCFollowupGuidance turns graph_overview strategy fields into planner-only
// instructions. It never calls add_intent itself and does not lower report_finding bar.
func renderPOCFollowupGuidance(data map[string]any) string {
	if data == nil || !plannerPOCFollowupEnabled() {
		return ""
	}
	rawC, _ := data["poc_verification_candidates"].([]map[string]any)
	rawB, _ := data["blocked_poc_retries"].([]map[string]any)
	var needC, needB []map[string]any
	for _, c := range rawC {
		if v, _ := c["needs_followup"].(bool); v {
			needC = append(needC, c)
		}
	}
	for _, b := range rawB {
		if v, _ := b["needs_followup"].(bool); v {
			needB = append(needB, b)
		}
	}
	if len(needC) == 0 && len(needB) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【漏洞验证跟进（策略层；不得用 record_fact 代替 report_finding 收官，worker 仍需可复现 PoC 才能 report_finding）】\n")
	if len(needC) > 0 {
		j, _ := json.Marshal(needC)
		b.WriteString("以下事实已构成漏洞验证候选（poc_verification_candidates），当前 frontier 未用 parent_ids 覆盖，本轮应 add_intent 派 worker 索取可复现 PoC，parent_ids 绑定 fact_id：\n")
		b.Write(j)
		b.WriteByte('\n')
	}
	if len(needB) > 0 {
		j, _ := json.Marshal(needB)
		b.WriteString("以下 blocked 验证/模型故障意图在事实已充足时可重新规划（blocked_poc_retries）；永久 llm_quota_exhausted 不在此列。可新建验证意图或等待 model_retry 自动 reopen，勿无差异重复：\n")
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.String()
}
