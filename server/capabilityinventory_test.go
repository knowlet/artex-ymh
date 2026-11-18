package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/skillprovider"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

type capabilitySourceFixture struct {
	worker     *db.Agent
	tools      []*db.Tool
	skills     []string
	visibleMCP []int64
	mcps       []*db.MCPServer
	fail       string
	calls      int
	libraryID  string
}

func (s *capabilitySourceFixture) check(stage string) error {
	s.calls++
	if stage == s.fail {
		return errors.New("SECRET_RAW_CONFIGURATION_ERROR")
	}
	return nil
}
func (s *capabilitySourceFixture) GetAgentByKey(key string) (*db.Agent, error) {
	if key != "worker" {
		return nil, errors.New("unexpected agent")
	}
	return s.worker, s.check("worker")
}
func (s *capabilitySourceFixture) ListTools() ([]*db.Tool, error) {
	return s.tools, s.check("tools")
}
func (s *capabilitySourceFixture) AgentSkillNamesInLibrary(id int64, library string) ([]string, error) {
	s.libraryID = library
	return s.skills, s.check("skills")
}
func (s *capabilitySourceFixture) AgentVisible(id int64, kind string) ([]int64, error) {
	if kind != "mcp" {
		return nil, errors.New("unexpected visibility kind")
	}
	return s.visibleMCP, s.check("visibility")
}
func (s *capabilitySourceFixture) ListMCP() ([]*db.MCPServer, error) {
	return s.mcps, s.check("mcp")
}

func capabilityFixture(t *testing.T) (*capabilitySourceFixture, string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"visible-directory":   "---\nname: visible-browser\ndescription: Browser workflow metadata\nmcps: [gated-server]\n---\nSECRET_SKILL_BODY\n",
		"invisible-directory": "---\nname: hidden-skill\ndescription: SECRET_INVISIBLE_SKILL\nmcps: [hidden-server]\n---\nSECRET_HIDDEN_BODY\n",
	} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "SKILL.md"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	worker := []string{"worker"}
	return &capabilitySourceFixture{
		worker: &db.Agent{ID: 42, Key: "worker", Enabled: true},
		tools: []*db.Tool{
			{Key: "record_fact", Kind: "builtin", Description: "Record observed facts", Enabled: true, Agents: worker},
			{Key: "browser_custom", Kind: "http", Description: "Browser metadata query", Enabled: true, Agents: worker, Deferred: true,
				Schema: json.RawMessage(`{"default":"SECRET_DEFAULT"}`), Exec: json.RawMessage(`{"url":"SECRET_EXEC"}`)},
			{Key: "shell_fixture", Kind: "shell", Description: "Declared local command", Enabled: true, Agents: worker},
			{Key: "disabled", Kind: "builtin", Description: "SECRET_DISABLED", Enabled: false, Agents: worker},
			{Key: "unbound", Kind: "builtin", Description: "SECRET_UNBOUND", Enabled: true, Agents: []string{"planner"}},
		},
		skills: []string{"visible-directory"}, visibleMCP: []int64{1, 3},
		mcps: []*db.MCPServer{
			{ID: 1, Name: "direct-server", Enabled: true, Command: "SECRET_COMMAND", Args: json.RawMessage(`["SECRET_ARGS"]`), Env: json.RawMessage(`{"TOKEN":"SECRET_ENV"}`), URL: "https://SECRET_ENDPOINT.invalid", Tools: []string{"SECRET_CACHED_TOOL"}},
			{ID: 2, Name: "gated-server", Enabled: true, Tools: []string{"SECRET_GATED_CACHE"}},
			{ID: 3, Name: "disabled-server", Enabled: false},
			{ID: 4, Name: "hidden-server", Enabled: true},
		},
	}, dir
}

func capabilityCall(t *testing.T, tool actool.CoreTool, input string) (workerCapabilityPage, string) {
	t.Helper()
	r, err := tool.Call(t.Context(), json.RawMessage(input), nil)
	if err != nil || r.IsError {
		t.Fatalf("inventory error=%v result=%s", err, r.Flatten())
	}
	var page workerCapabilityPage
	if err := json.Unmarshal([]byte(r.Flatten()), &page); err != nil {
		t.Fatal(err)
	}
	return page, r.Flatten()
}

func TestWorkerCapabilityInventoryMetadata(t *testing.T) {
	source, dir := capabilityFixture(t)
	tool := newWorkerCapabilitiesTool(source, dir)
	page, raw := capabilityCall(t, tool, `{}`)
	if !tool.IsReadOnly(nil) || !page.WorkerEnabled || page.RuntimeVerified {
		t.Fatal("inventory must be read-only configuration metadata")
	}
	var names []string
	for _, item := range page.Items {
		names = append(names, item.Name)
		if item.Name == "gated-server" && !reflect.DeepEqual(item.SkillAlternatives, []string{"visible-browser"}) {
			t.Fatalf("missing exact visible skill prerequisite: %+v", item)
		}
	}
	want := []string{"browser_custom", "direct-server", "gated-server", "record_fact", "shell_fixture", "visible-browser"}
	if !reflect.DeepEqual(names, want) || page.TotalMatches != len(want) || page.NextOffset != nil {
		t.Fatalf("wrong inventory: %s", raw)
	}
	for _, forbidden := range []string{"SECRET_", "hidden-server", "disabled-server", "hidden-skill", "schema", "exec_spec"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("inventory exposed forbidden field/value %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(page.Note, "configured does not mean") || !strings.Contains(raw, "SearchExtraTools") {
		t.Fatal("missing configuration/runtime distinction or discovery route")
	}
	if source.calls != 5 {
		t.Fatalf("unexpected metadata read count: %d", source.calls)
	}
	filtered, _ := capabilityCall(t, tool, `{"query":"browser metadata"}`)
	if filtered.TotalMatches != 2 {
		t.Fatalf("keyword query should match tool and skill: %+v", filtered)
	}
	privateQuery, _ := capabilityCall(t, tool, `{"query":"SECRET_DEFAULT"}`)
	if privateQuery.TotalMatches != 0 {
		t.Fatal("query searched private configuration fields")
	}
}

func TestWorkerCapabilityInventoryPaginationAndBounds(t *testing.T) {
	source, dir := capabilityFixture(t)
	tool := newWorkerCapabilitiesTool(source, dir)
	var names []string
	offset := 0
	for {
		page, raw := capabilityCall(t, tool, fmt.Sprintf(`{"limit":2,"offset":%d}`, offset))
		if len(page.Items) > 2 || len(raw) > workerCapabilityMaxBytes {
			t.Fatal("unbounded inventory page")
		}
		for _, item := range page.Items {
			names = append(names, item.Name)
		}
		if page.NextOffset == nil {
			break
		}
		if *page.NextOffset <= offset {
			t.Fatal("pagination made no progress")
		}
		offset = *page.NextOffset
	}
	if len(uniqueSortedNames(names)) != 6 || len(names) != 6 {
		t.Fatalf("missing or duplicated entries across pages: %v", names)
	}
	page, _ := capabilityCall(t, tool, `{"offset":9223372036854775807}`)
	if len(page.Items) != 0 || page.NextOffset != nil {
		t.Fatal("offset past end must return an empty terminal page")
	}
	for _, raw := range []string{`{"limit":51}`, `{"limit":-1}`, `{"offset":-1}`, `{"query":"` + strings.Repeat("x", 257) + `"}`, `[]`} {
		before := source.calls
		r, err := tool.Call(t.Context(), json.RawMessage(raw), nil)
		if err != nil || !r.IsError || source.calls != before {
			t.Fatalf("invalid query reached configuration reads: %s", raw)
		}
	}
	// Escaped descriptions exercise the byte budget independently of the row cap.
	source.tools, source.skills, source.visibleMCP, source.mcps = nil, nil, nil, nil
	for i := 0; i < 100; i++ {
		source.tools = append(source.tools, &db.Tool{Key: fmt.Sprintf("tool-%03d", i), Kind: "builtin", Description: strings.Repeat("<", 2000), Enabled: true, Agents: []string{"worker"}})
	}
	page, raw := capabilityCall(t, tool, `{"limit":50}`)
	if len(raw) > workerCapabilityMaxBytes || len(page.Items) == 0 || len(page.Items) >= 50 || page.NextOffset == nil {
		t.Fatalf("byte budget did not paginate: bytes=%d page=%+v", len(raw), page)
	}
	for _, item := range page.Items {
		if len(item.Description) > workerCapabilityMaxDesc || !utf8.ValidString(item.Description) {
			t.Fatal("description truncation invalid")
		}
	}
	if clipped := capabilityText(strings.Repeat("界", 300), workerCapabilityMaxDesc); !utf8.ValidString(clipped) || len(clipped) > workerCapabilityMaxDesc {
		t.Fatal("UTF-8 clipping exceeded bound")
	}
}

func TestWorkerCapabilityInventoryFailsClosed(t *testing.T) {
	for _, stage := range []string{"worker", "tools", "skills", "visibility", "mcp"} {
		t.Run(stage, func(t *testing.T) {
			source, dir := capabilityFixture(t)
			source.fail = stage
			r, err := newWorkerCapabilitiesTool(source, dir).Call(t.Context(), json.RawMessage(`{}`), nil)
			if err != nil || !r.IsError || strings.Contains(r.Flatten(), "SECRET_") || strings.Contains(r.Flatten(), "record_fact") {
				t.Fatalf("failed read exposed raw/partial data: %v %s", err, r.Flatten())
			}
		})
	}
	source, dir := capabilityFixture(t)
	source.worker.Enabled = false
	page, _ := capabilityCall(t, newWorkerCapabilitiesTool(source, dir), `{}`)
	if page.WorkerEnabled || len(page.Items) != 0 || source.calls != 1 {
		t.Fatal("disabled worker advertised executable configuration")
	}
	source.worker.Enabled = true
	// An imported-library marker without its receipt cannot reuse legacy grants.
	if err := os.WriteFile(filepath.Join(dir, skillprovider.LibraryIDFilename), []byte("missing-receipt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := newWorkerCapabilitiesTool(source, dir).Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil || !r.IsError || strings.Contains(r.Flatten(), "record_fact") {
		t.Fatal("unverified library returned partial capabilities")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := source.calls
	r, _ = newWorkerCapabilitiesTool(source, dir).Call(ctx, json.RawMessage(`{}`), nil)
	if !r.IsError || source.calls != before {
		t.Fatal("cancelled request read configuration")
	}
}

func TestSkillGatedDiscoveryPrerequisites(t *testing.T) {
	calls := 0
	base := actool.Build(actool.Spec{Name: "mcp__fixture__inspect", Description: "Inspect the fixture", Prompt: "original prompt",
		Schema:   map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "default": "must-not-inject"}}},
		ReadOnly: func(json.RawMessage) bool { return true }, Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Denied("original permission")
		},
		Run: func(_ context.Context, raw json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			calls++
			return actool.Text(string(raw)), nil
		},
	})
	wrapped := withSkillPrerequisites(base, []string{"browser-b", "browser-a", "browser-a"})
	if wrapped.Name() != base.Name() || wrapped.Prompt() != base.Prompt() || !reflect.DeepEqual(wrapped.InputSchema(), base.InputSchema()) ||
		!wrapped.IsReadOnly(nil) || !wrapped.IsConcurrencySafe(nil) || wrapped.CheckPermissions(t.Context(), nil, permission.Context{}).Behavior != permission.Deny {
		t.Fatal("description enrichment changed tool identity/permissions/schema")
	}
	reg := actool.NewRegistry(wrapped)
	unlock := actool.NewUnlockSet()
	search := actool.NewSearchExtraTools(reg, []string{wrapped.Name()})
	r, err := search.Call(t.Context(), json.RawMessage(`{"query":"select:mcp__fixture__inspect"}`), nil)
	if err != nil || r.IsError || !strings.Contains(r.Flatten(), `["browser-a","browser-b"]`) || calls != 0 || unlock.Has(wrapped.Name()) {
		t.Fatalf("search did not disclose prerequisites safely: %v %s", err, r.Flatten())
	}
	execute := actool.NewExecuteExtraTool(reg, unlock)
	input := json.RawMessage(`{"tool_name":"mcp__fixture__inspect","params":{}}`)
	r, _ = execute.Call(t.Context(), input, nil)
	if !r.IsError || calls != 0 {
		t.Fatal("search bypassed skill gate")
	}
	skills := skill.NewRegistry()
	skills.Add(skill.Skill{Name: "browser-a", Instructions: "Harmless fixture instructions"})
	skills.OnInvoke = func(skill.Skill) string { unlock.Add(wrapped.Name()); return "" }
	if r, err = skills.Tool().Call(t.Context(), json.RawMessage(`{"name":"browser-a"}`), nil); err != nil || r.IsError {
		t.Fatal("fixture skill failed")
	}
	r, err = execute.Call(t.Context(), input, nil)
	if err != nil || r.IsError || calls != 1 || r.Flatten() != `{}` {
		t.Fatalf("unlocked behavior/defaults changed: %v %s", err, r.Flatten())
	}
}

func TestWorkerCapabilityInventoryBindingsPG(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		if os.Getenv("ARTEX_ADAPTIVE_REQUIRE_PG") == "1" {
			t.Fatal(err)
		}
		t.Skipf("PostgreSQL not configured: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	s := &Server{m: &Manager{pg: pg}, skillDir: t.TempDir()}
	tool := s.toolListWorkerCapabilities()
	original, err := pg.GetTool(tool.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if original == nil {
			_, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, tool.Name())
		} else {
			raw, _ := json.Marshal(original.Agents)
			_ = pg.UpdateTool(original.Key, original.Description, original.Schema, raw, original.Enabled)
		}
	})
	if _, err := pg.Exec(`DELETE FROM tools WHERE key=$1`, tool.Name()); err != nil {
		t.Fatal(err)
	}
	s.seedWorkerCapabilitiesTool()
	row, err := pg.GetTool(tool.Name())
	if err != nil || row == nil || !row.Enabled || !reflect.DeepEqual(row.Agents, []string{"planner"}) {
		t.Fatalf("inventory default binding: %+v %v", row, err)
	}
	originalResolve := agent.ToolResolve
	t.Cleanup(func() { agent.ToolResolve = originalResolve })
	wireTools(pg, nil)
	hasInventory := func(role string) bool {
		for _, resolved := range agent.ToolResolve(t.Context(), role, []actool.CoreTool{tool}) {
			if resolved.Name() == tool.Name() {
				return true
			}
		}
		return false
	}
	if !hasInventory("planner") {
		t.Fatal("planner did not receive bound inventory")
	}
	if hasInventory("worker") {
		t.Fatal("inventory leaked into an unbound role")
	}
	capabilityCall(t, tool, `{"limit":1}`) // actual PG metadata read, no runtime assembly
	if err := pg.UpdateTool(row.Key, "User description", row.Schema, json.RawMessage(`["mainagent"]`), false); err != nil {
		t.Fatal(err)
	}
	s.seedWorkerCapabilitiesTool()
	row, err = pg.GetTool(tool.Name())
	if err != nil || row.Enabled || row.Description != "User description" || !reflect.DeepEqual(row.Agents, []string{"mainagent"}) {
		t.Fatal("seeding overwrote user capability inventory settings")
	}
	if hasInventory("planner") {
		t.Fatal("disabled inventory remained callable")
	}
}
