package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/skillprovider"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

// Only Description changes. In particular, do not use a parameter-default
// decorator here: discovery must not change a connected MCP tool's inputs,
// permissions, handler, or unlock gate.
type skillPrerequisiteTool struct {
	actool.CoreTool
	description string
}

func (t *skillPrerequisiteTool) Description() string { return t.description }

func withSkillPrerequisites(t actool.CoreTool, alternatives []string) actool.CoreTool {
	if len(alternatives) == 0 {
		return t
	}
	names := uniqueSortedNames(alternatives)
	raw, _ := json.Marshal(names)
	return &skillPrerequisiteTool{CoreTool: t, description: t.Description() +
		"\n\nSkill prerequisite: if this tool is still locked, load ONE of these visible skills with Skill({\"name\":\"exact skill name\"}): " + string(raw) +
		". These are alternatives, not cumulative requirements. Then use SearchExtraTools and ExecuteExtraTool as usual."}
}

func uniqueSortedNames(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range names {
		if name != "" && !seen[name] {
			out = append(out, name)
			seen[name] = true
		}
	}
	sort.Strings(out)
	return out
}

// This read-only interface deliberately has no execution, MCP connection,
// tool creation, or visibility mutation methods. The inventory is configuration
// metadata for delegation, never a second executable tool registry.
type workerCapabilitySource interface {
	GetAgentByKey(string) (*db.Agent, error)
	ListTools() ([]*db.Tool, error)
	AgentSkillNamesInLibrary(int64, string) ([]string, error)
	AgentVisible(int64, string) ([]int64, error)
	ListMCP() ([]*db.MCPServer, error)
}

const (
	workerCapabilityDefaultLimit = 20
	workerCapabilityMaxLimit     = 50
	workerCapabilityMaxBytes     = 24 * 1024
	workerCapabilityMaxName      = 256
	workerCapabilityMaxDesc      = 480
)

type workerCapabilityQuery struct {
	Query  string `json:"query"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

type workerCapability struct {
	Kind                  string   `json:"kind"`
	Name                  string   `json:"name"`
	Description           string   `json:"description,omitempty"`
	Access                string   `json:"access"`
	SkillAlternatives     []string `json:"skill_alternatives,omitempty"`
	MoreSkillAlternatives int      `json:"more_skill_alternatives,omitempty"`
}

type workerCapabilityPage struct {
	Agent                 string             `json:"agent"`
	WorkerEnabled         bool               `json:"worker_enabled"`
	RuntimeVerified       bool               `json:"runtime_verified"`
	Note                  string             `json:"note"`
	Items                 []workerCapability `json:"items"`
	TotalMatches          int                `json:"total_matches"`
	Offset                int                `json:"offset"`
	Limit                 int                `json:"limit"`
	NextOffset            *int               `json:"next_offset,omitempty"`
	OmittedOversizedNames int                `json:"omitted_oversized_names,omitempty"`
}

func (s *Server) toolListWorkerCapabilities() actool.CoreTool {
	var source workerCapabilitySource
	if s.m != nil && s.m.pg != nil {
		source = s.m.pg
	}
	return newWorkerCapabilitiesTool(source, s.skillDir)
}

func newWorkerCapabilitiesTool(source workerCapabilitySource, skillDir string) actool.CoreTool {
	return roTool("list_worker_capabilities",
		"查询 worker 的配置能力元数据，供规划委派选择工具/技能。仅含启用且绑定 worker 的受管工具/命令行声明、可见本地技能、配置启用的可见 MCP 服务。配置不代表当前任务中已连接或可运行，也不授予 planner 调用这些工具的权限；worker 仍用自己的工具列表、Skill 和 SearchExtraTools 完成实际发现并遵守任务约束。不会连接 MCP、执行命令、加载技能或改变绑定。可用 query 过滤、limit/offset 分页；不返回执行规格、参数默认值、连接地址或凭据。",
		objSchema(map[string]any{
			"query":  map[string]any{"type": "string", "description": "可选名称/描述关键词（多个词同时匹配）；空字符串列出配置元数据。最多 256 字节。", "maxLength": 256},
			"limit":  map[string]any{"type": "integer", "description": "每页条数，默认 20，最多 50；还受总输出大小限制。", "minimum": 1, "maximum": workerCapabilityMaxLimit},
			"offset": map[string]any{"type": "integer", "description": "起始位置，默认 0；用上页 next_offset 继续。配置变更后请从 0 重新查询。", "minimum": 0},
		}),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var q workerCapabilityQuery
			if err := json.Unmarshal(raw, &q); err != nil {
				return actool.Errorf("Invalid capability query: expected a JSON object with query, limit, and offset."), nil
			}
			if q.Limit == 0 {
				q.Limit = workerCapabilityDefaultLimit
			}
			if len(q.Query) > 256 || q.Limit < 1 || q.Limit > workerCapabilityMaxLimit || q.Offset < 0 {
				return actool.Errorf("Invalid capability query: query must be at most 256 bytes, limit 1–50, and offset nonnegative."), nil
			}
			page, err := readWorkerCapabilities(ctx, source, skillDir, q)
			if err != nil {
				// Do not return raw DB/filesystem errors: they may contain connection
				// details. Never fall back to cached or unfiltered capabilities.
				return actool.Errorf("Worker capability metadata unavailable: " + err.Error() + ". No capability list was returned; retry after configuration access is restored."), nil
			}
			return jsonResult(page)
		})
}

func readWorkerCapabilities(ctx context.Context, source workerCapabilitySource, skillDir string, q workerCapabilityQuery) (workerCapabilityPage, error) {
	page := workerCapabilityPage{
		Agent: "worker", Items: []workerCapability{}, Offset: q.Offset, Limit: q.Limit,
		Note: "Delegation metadata only: configured does not mean connected, installed, or callable in the current task. Task scope, approvals, runtime settings, and the worker session still control execution. Covers managed worker-bound tools, visible local skills, and configured MCP servers; session-native SDK tools are not enumerated. Descriptions may be shortened. No MCP connection or tool/skill invocation was performed.",
	}
	if err := ctx.Err(); err != nil {
		return page, errors.New("request cancelled")
	}
	if source == nil {
		return page, errors.New("configuration store is unavailable")
	}
	worker, err := source.GetAgentByKey("worker")
	if err != nil || worker == nil {
		return page, errors.New("worker configuration could not be read")
	}
	page.WorkerEnabled = worker.Enabled
	if !worker.Enabled {
		return page, nil
	}
	tools, err := source.ListTools()
	if err != nil {
		return page, errors.New("tool bindings could not be read")
	}
	libraryID, err := skillprovider.LibraryIdentity(skillDir)
	if err != nil {
		return page, errors.New("skill library identity could not be verified")
	}
	skillNames, err := source.AgentSkillNamesInLibrary(worker.ID, libraryID)
	if err != nil {
		return page, errors.New("skill visibility could not be read")
	}
	visibleSkills := map[string]bool{}
	for _, name := range skillNames {
		visibleSkills[name] = true
	}
	var skills []skill.Skill
	if len(visibleSkills) > 0 {
		reg, err := skill.LoadDir(skillDir)
		if err != nil {
			return page, errors.New("local skill metadata could not be read")
		}
		for _, item := range reg.List() {
			// Use the same directory-key visibility rule as wireAgentAugment.
			if item.Dir != "" && visibleSkills[filepath.Base(item.Dir)] {
				skills = append(skills, item)
			}
		}
	}
	mcpIDs, err := source.AgentVisible(worker.ID, "mcp")
	if err != nil {
		return page, errors.New("MCP visibility could not be read")
	}
	mcps, err := source.ListMCP()
	if err != nil {
		return page, errors.New("MCP configuration could not be read")
	}
	if ctx.Err() != nil {
		return page, errors.New("request cancelled")
	}

	// All required reads succeeded. Build an explicit allowlist of output fields;
	// never serialize DB objects, parameter schemas, execution specs, MCP env/URL,
	// cached tool names, or skill instruction bodies.
	var items []workerCapability
	tokens := strings.Fields(strings.ToLower(q.Query))
	add := func(item workerCapability) {
		haystack := strings.ToLower(item.Kind + " " + item.Name + " " + item.Description)
		for _, token := range tokens {
			if !strings.Contains(haystack, token) {
				return
			}
		}
		if item.Name == "" || len(item.Name) > workerCapabilityMaxName {
			page.OmittedOversizedNames++
			return
		}
		item.Description = capabilityText(item.Description, workerCapabilityMaxDesc)
		items = append(items, item)
	}
	for _, t := range tools {
		if t == nil || !t.Enabled || !contains(t.Agents, "worker") {
			continue
		}
		item := workerCapability{Name: t.Key, Description: t.Description, Access: "worker tool list"}
		switch t.Kind {
		case "", "builtin":
			item.Kind = "native_tool"
		case "command", "script", "http":
			item.Kind = "custom_tool"
			if t.Deferred {
				item.Access = "worker SearchExtraTools then ExecuteExtraTool"
			}
		case "shell":
			item.Kind, item.Access = "shell_tool", "worker Bash; installation is declared, not verified"
		default:
			continue
		}
		add(item)
	}
	skillAlternatives := map[string][]string{}
	for _, item := range skills {
		desc := item.Description
		if desc == "" {
			desc = item.WhenToUse
		}
		add(workerCapability{Kind: "skill", Name: item.Name, Description: desc, Access: "worker Skill"})
		for _, server := range item.MCPs {
			skillAlternatives[server] = append(skillAlternatives[server], item.Name)
		}
	}
	want := idSet(mcpIDs)
	for _, m := range mcps {
		if m == nil || !m.Enabled || (!want[m.ID] && len(skillAlternatives[m.Name]) == 0) {
			continue
		}
		item := workerCapability{Kind: "mcp_server", Name: m.Name,
			Description: "Configured MCP server; individual tools and connection status must be discovered in the worker session.",
			Access:      "worker SearchExtraTools then ExecuteExtraTool, if connected"}
		if alternatives := uniqueSortedNames(skillAlternatives[m.Name]); len(alternatives) > 0 {
			item.Access = "worker Skill prerequisite, then SearchExtraTools and ExecuteExtraTool, if connected"
			for _, name := range alternatives {
				if len(item.SkillAlternatives) < 4 && len(name) <= workerCapabilityMaxName {
					item.SkillAlternatives = append(item.SkillAlternatives, name)
				} else {
					item.MoreSkillAlternatives++
				}
			}
		}
		add(item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Name < items[j].Name
	})
	page.TotalMatches = len(items)
	if q.Offset >= len(items) {
		return page, nil
	}
	for i := q.Offset; i < len(items) && len(page.Items) < q.Limit; i++ {
		page.Items = append(page.Items, items[i])
		next := i + 1
		if next < len(items) {
			page.NextOffset = &next
		} else {
			page.NextOffset = nil
		}
		raw, _ := json.Marshal(page)
		if len(raw) > workerCapabilityMaxBytes {
			page.Items = page.Items[:len(page.Items)-1]
			page.NextOffset = &i
			break
		}
	}
	return page, nil
}

func capabilityText(text string, maxBytes int) string {
	if len(text) <= maxBytes {
		return text
	}
	text = text[:maxBytes-len("…")]
	for !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text + "…"
}

func (s *Server) seedWorkerCapabilitiesTool() {
	t := s.toolListWorkerCapabilities()
	schema, _ := json.Marshal(t.InputSchema())
	// First-insert semantics preserve later user binding/description/enable edits.
	if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, json.RawMessage(`["planner"]`)); err != nil {
		log.Printf("[tools] seed %s failed: %v", t.Name(), err)
	}
}
