package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/context1337"
	actool "github.com/Autumn-27/norma/tool"
)

func TestContext1337CatalogRequiresExplicitBinding(t *testing.T) {
	count := 0
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key != context1337.ToolName {
			continue
		}
		count++
		if seed.Agents == nil || len(seed.Agents) != 0 {
			t.Fatalf("metadata lookup must be explicitly bound, got %v", seed.Agents)
		}
		if seed.Desc == "" || len(seed.Schema) == 0 {
			t.Fatal("metadata lookup catalog is incomplete")
		}
	}
	if count != 1 {
		t.Fatalf("metadata lookup seed count = %d", count)
	}
	for role, tools := range builtinToolsByAgent() {
		found := false
		for _, tool := range tools {
			found = found || tool.Name() == context1337.ToolName
		}
		if found != (role == "planner" || role == "worker") {
			t.Fatalf("metadata lookup catalog candidate for %s = %v", role, found)
		}
	}
}

func TestContext1337GuidanceUsesFinalPermittedTools(t *testing.T) {
	oldAugment, oldResolve := ToolAugment, ToolResolve
	t.Cleanup(func() { ToolAugment, ToolResolve = oldAugment, oldResolve })
	lookup := context1337.Tool(nil, nil)
	for _, role := range []string{"planner", "worker"} {
		t.Run(role, func(t *testing.T) {
			ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
				return []actool.CoreTool{lookup}, DeferredInfo{MetadataGuidance: "stale guidance"}, nil
			}
			ToolResolve = func(_ context.Context, _ string, tools []actool.CoreTool) []actool.CoreTool {
				return []actool.CoreTool{DecorateTool(tools[0], "operator-edited description", nil)}
			}
			tools, def, cleanup := AugmentTools(t.Context(), role, nil)
			cleanup()
			if len(tools) != 1 || tools[0].Description() != "operator-edited description" {
				t.Fatal("catalog override was not preserved")
			}
			if def.MetadataGuidance != context1337ExerciseGuidance {
				t.Fatalf("missing fixed metadata boundary: %q", def.MetadataGuidance)
			}
			system, _ := deferredSystem("CUSTOM PROMPT", def)
			if !strings.HasPrefix(system[0], "CUSTOM PROMPT") || !strings.Contains(system[0], context1337ExerciseGuidance) {
				t.Fatal("fixed guidance did not survive editable prompt")
			}
			ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
			_, removed, cleanup := AugmentTools(t.Context(), role, nil)
			cleanup()
			if removed.MetadataGuidance != "" {
				t.Fatal("filtered metadata tool still advertised")
			}
			system, _ = deferredSystem("CUSTOM PROMPT", removed)
			if strings.Contains(system[0], context1337.ToolName) || strings.Contains(system[0], "stale guidance") {
				t.Fatal("unavailable metadata tool retained prompt guidance")
			}
		})
	}
}

func TestContext1337NotInDefaultOrTasklessDomainTools(t *testing.T) {
	oldAugment, oldResolve := ToolAugment, ToolResolve
	t.Cleanup(func() { ToolAugment, ToolResolve = oldAugment, oldResolve })
	ToolAugment, ToolResolve = nil, nil
	ts := NewToolSet(nil, "")
	for role, base := range map[string][]actool.CoreTool{
		"planner": ts.PlannerTools(), "worker": ts.WorkerTools(),
		"mainagent": ts.MainAgentTools(), "auto": ts.AllDomainTools(),
	} {
		tools, def, cleanup := AugmentTools(t.Context(), role, base)
		cleanup()
		for _, tool := range tools {
			if tool.Name() == context1337.ToolName {
				t.Fatalf("metadata lookup leaked into default/taskless %s tools", role)
			}
		}
		if def.MetadataGuidance != "" {
			t.Fatalf("default/taskless %s received metadata guidance", role)
		}
	}
}
