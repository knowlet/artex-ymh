package agent

import (
	"context"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestCapabilityGuidanceFinalResolvedTools(t *testing.T) {
	oldAugment, oldResolve := ToolAugment, ToolResolve
	t.Cleanup(func() { ToolAugment, ToolResolve = oldAugment, oldResolve })
	tool := func(name string) actool.CoreTool { return actool.Build(actool.Spec{Name: name}) }
	unlock := actool.NewUnlockSet("keep", "removed")
	ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		return []actool.CoreTool{tool("keep"), tool("removed"), tool("Skill")}, DeferredInfo{
			Deferred:    []string{"keep", "removed", "keep", "missing"},
			GlobalNames: []string{"keep", "removed", "missing", "Bash"}, Unlock: unlock,
		}, nil
	}
	ToolResolve = func(_ context.Context, _ string, tools []actool.CoreTool) []actool.CoreTool {
		var out []actool.CoreTool
		for _, item := range tools {
			if item.Name() != "removed" && item.Name() != "Skill" {
				out = append(out, item)
			}
		}
		return out
	}
	_, def, cleanup := AugmentTools(t.Context(), "planner", []actool.CoreTool{tool("Bash"), tool("list_worker_capabilities")})
	defer cleanup()
	if strings.Join(def.Deferred, ",") != "keep" || strings.Join(def.GlobalNames, ",") != "keep" {
		t.Fatalf("deferred disclosure not resolved: %+v", def)
	}
	if def.Unlock != unlock || !unlock.Has("removed") {
		t.Fatal("metadata reconciliation changed execution gating")
	}
	for _, name := range []string{"SearchExtraTools", "ExecuteExtraTool", "Bash", "list_worker_capabilities", "next_offset"} {
		if !strings.Contains(def.RecoveryGuidance, name) {
			t.Fatalf("missing actual route %s: %s", name, def.RecoveryGuidance)
		}
	}
	if strings.Contains(def.RecoveryGuidance, "Skill(") {
		t.Fatal("removed Skill still advertised")
	}
	system, _ := deferredSystem("CUSTOM PROMPT", def)
	if !strings.HasPrefix(system[0], "CUSTOM PROMPT") || !strings.Contains(system[0], def.RecoveryGuidance) {
		t.Fatal("recovery guidance not appended to existing prompt")
	}
}

func TestCapabilityGuidanceUnavailableRoutes(t *testing.T) {
	tools := []actool.CoreTool{actool.Build(actool.Spec{Name: "Skill"})}
	def := resolvedDeferredInfo(tools, DeferredInfo{
		Deferred: []string{"filtered"}, GlobalNames: []string{"filtered"}, RecoveryGuidance: "STALE GUIDANCE",
	})
	if !strings.Contains(def.RecoveryGuidance, "Skill(") {
		t.Fatal("available Skill missing")
	}
	for _, absent := range []string{"SearchExtraTools", "ExecuteExtraTool", "Bash", "list_worker_capabilities", "STALE GUIDANCE"} {
		if strings.Contains(def.RecoveryGuidance, absent) {
			t.Fatalf("advertised unavailable route %s", absent)
		}
	}
	if len([]byte(def.RecoveryGuidance)) > 4096 {
		t.Fatal("recovery guidance must remain bounded")
	}
	empty := resolvedDeferredInfo(nil, DeferredInfo{RecoveryGuidance: "stale"})
	if empty.RecoveryGuidance != "" {
		t.Fatal("empty registry retained recovery guidance")
	}
	all := capabilityRecoveryGuidance(map[string]bool{"Skill": true, "Bash": true, "list_worker_capabilities": true}, true)
	if len([]byte(all)) > 4096 {
		t.Fatal("all recovery routes exceed fixed context budget")
	}
}
