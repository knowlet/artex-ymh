package agent

import (
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// resolvedDeferredInfo reconciles disclosure with the final resolved registry.
// It never changes the registry, binding policy, or unlock set. In particular,
// a custom tool removed by ToolResolve must not remain advertised as deferred.
func resolvedDeferredInfo(tools []actool.CoreTool, def DeferredInfo) DeferredInfo {
	present := make(map[string]bool, len(tools))
	for _, t := range tools {
		present[t.Name()] = true
	}
	intersect := func(names []string, allowed map[string]bool) []string {
		var out []string
		seen := make(map[string]bool, len(names))
		for _, name := range names {
			if allowed[name] && !seen[name] {
				out = append(out, name)
				seen[name] = true
			}
		}
		return out
	}
	def.Deferred = intersect(def.Deferred, present)
	deferred := make(map[string]bool, len(def.Deferred))
	for _, name := range def.Deferred {
		deferred[name] = true
	}
	def.GlobalNames = intersect(def.GlobalNames, deferred)
	def.RecoveryGuidance = capabilityRecoveryGuidance(present, len(def.Deferred) > 0)
	return def
}

// Only describe access routes that this session actually has. Tool schemas and
// descriptions remain the detailed catalog; this small reminder supplies the
// missing link between a blocked approach and the existing discovery surfaces.
func capabilityRecoveryGuidance(present map[string]bool, hasDeferred bool) string {
	var routes []string
	if hasDeferred {
		routes = append(routes, `延迟工具：用 SearchExtraTools({"query":"关键字"}) 查名称/描述（多个词必须同时匹配，无结果时减少关键词）；已知确切名称可用 {"query":"select:完整名称"} 取 schema，再用 ExecuteExtraTool({"tool_name":"完整名称","params":{...}})。若工具仍锁定，先按结果中的前置条件加载对应技能。`)
	}
	if present["Skill"] {
		routes = append(routes, `技能：先查看 Skill 的可用技能说明，匹配当前问题时用 Skill({"name":"确切技能名"}) 加载；加载技能不代表其外部依赖已经连接成功。`)
	}
	if present["Bash"] {
		routes = append(routes, "命令行：查看 Bash 描述中为本角色声明的工具；声明不是运行验证，命令不存在或依赖失败时保留具体错误并选择适用的现有替代能力。")
	}
	if present["list_worker_capabilities"] {
		routes = append(routes, `委派前可用 list_worker_capabilities({"query":"所需能力关键词","limit":20,"offset":0}) 查看 worker 的配置元数据，按 next_offset 翻页。它不授予调用权，也不证明当前任务中可运行；实际工具发现、前置技能和任务范围检查仍由 worker 会话完成。`)
	}
	if len(routes) == 0 {
		return ""
	}
	return "\n\n**受阻时的能力选择**：根据具体失败原因查找能改变验证方式的现有能力，保持当前任务范围、约束与角色职责；不要把换工具本身当成进展。\n" + strings.Join(routes, "\n")
}
