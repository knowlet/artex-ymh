package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/skillprovider"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/google/uuid"
)

// Real PG + real Norma assembly: search must observe the same grants, library
// identity and editable tool bindings as the Skill meta-tool, on a fresh run.
func TestAntiFoxKnowledgeVisibilityPG(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		if os.Getenv("ARTEX_ANTIFOX_REQUIRE_PG") == "1" {
			t.Fatal(err)
		}
		t.Skipf("PostgreSQL not configured: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		if os.Getenv("ARTEX_ANTIFOX_REQUIRE_PG") == "1" {
			t.Fatal(err)
		}
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	key := "antifox_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ag, err := pg.CreateAgent(key, "Knowledge fixture", "Harmless visibility test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteAgent(key) })
	root := t.TempDir()
	for name, body := range map[string]string{"visible": "orchiduniquemarker procedure", "hidden": "hiddenuniquemarker confidential reference"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\ndescription: benign reference\n---\n"+body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.ToggleSkillVisibility(ag.ID, "visible", true); err != nil {
		t.Fatal(err)
	}
	previousAugment, previousResolve, previousBinding := agent.ToolAugment, agent.ToolResolve, agent.FindingTrafficBindingEnabled
	t.Cleanup(func() {
		agent.ToolAugment = previousAugment
		agent.ToolResolve = previousResolve
		agent.FindingTrafficBindingEnabled = previousBinding
	})
	wireAgentAugment(pg, root, nil)
	wireTools(pg, nil)
	// The provider importer also consumes raw augmentation, before ToolResolve.
	// A fresh custom agent must receive only Skill until explicitly tool-bound.
	unbound, _, cleanup := agent.ToolAugment(t.Context(), key)
	cleanup()
	if len(unbound) != 1 || unbound[0].Name() != "Skill" {
		t.Fatal("unbound agent received additional tools", names(unbound))
	}
	row, err := pg.GetTool("search_knowledge")
	if err != nil || row == nil {
		t.Fatalf("tool not seeded: %v", err)
	}
	defer func() { _ = pg.UpdateTool(row.Key, row.Description, row.Schema, mustJSON(row.Agents), row.Enabled) }()
	if err := pg.UpdateTool(row.Key, row.Description, row.Schema, mustJSON([]string{key}), true); err != nil {
		t.Fatal(err)
	}
	assemble := func() map[string]actool.CoreTool {
		t.Helper()
		tools, _, cleanup := agent.AugmentTools(t.Context(), key, nil)
		cleanup()
		return names(tools)
	}
	search := func(query string) string {
		t.Helper()
		tool := assemble()["search_knowledge"]
		if tool == nil {
			t.Fatal("knowledge tool missing")
		}
		input, _ := json.Marshal(map[string]string{"query": query})
		result, err := tool.Call(t.Context(), input, nil)
		if err != nil || result.IsError || len(result.Extra) != 0 {
			t.Fatalf("lookup: %v %+v", err, result)
		}
		return result.Flatten()
	}
	if !strings.Contains(search("orchiduniquemarker"), "orchiduniquemarker") {
		t.Fatal("visible skill absent")
	}
	if strings.Contains(search("hiddenuniquemarker"), "hiddenuniquemarker") {
		t.Fatal("hidden skill leaked")
	}
	// A pre-existing custom tool with this key owns its handler. Startup seeding
	// must not silently replace it with the native knowledge implementation.
	if _, err := pg.Exec(`UPDATE tools SET system=false WHERE key=$1`, row.Key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`UPDATE tools SET system=true WHERE key=$1`, row.Key) })
	if assemble()["search_knowledge"] != nil {
		t.Fatal("native knowledge tool shadowed a custom tool")
	}
	if _, err := pg.Exec(`UPDATE tools SET system=true WHERE key=$1`, row.Key); err != nil {
		t.Fatal(err)
	}
	if err := pg.ToggleSkillVisibility(ag.ID, "visible", false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(search("orchiduniquemarker"), "orchiduniquemarker") {
		t.Fatal("revoked skill leaked into fresh run")
	}
	if err := pg.UpdateTool(row.Key, row.Description, row.Schema, mustJSON([]string{key}), false); err != nil {
		t.Fatal(err)
	}
	if assemble()["search_knowledge"] != nil {
		t.Fatal("disabled tool reintroduced")
	}
	// Re-seeding cannot restore an explicit tool disable or visibility disable.
	wireTools(pg, nil)
	if assemble()["search_knowledge"] != nil {
		t.Fatal("seed overwrote disabled tool")
	}
	if err := pg.UpdateTool(row.Key, row.Description, row.Schema, mustJSON([]string{key}), true); err != nil {
		t.Fatal(err)
	}
	if err := pg.ToggleSkillVisibility(ag.ID, "visible", true); err != nil {
		t.Fatal(err)
	}
	// An identified provider library must never inherit a legacy name grant. A
	// malformed identity fails closed on every platform, before tools get content.
	if err := os.WriteFile(filepath.Join(root, skillprovider.LibraryIDFilename), []byte(strings.Repeat("a", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(search("orchiduniquemarker"), "orchiduniquemarker") {
		t.Fatal("invalid provider identity leaked legacy grant")
	}
	if err := os.Remove(filepath.Join(root, skillprovider.LibraryIDFilename)); err != nil {
		t.Fatal(err)
	}
	worker, err := pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatal("worker missing", err)
	}
	grants, err := pg.AgentSkillNames(worker.ID)
	if err != nil {
		t.Fatal(err)
	}
	originalEnabled := slices.Contains(grants, "antifox-sql-injection-testing")
	if err := pg.ToggleSkillVisibility(worker.ID, "antifox-sql-injection-testing", false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.ToggleSkillVisibility(worker.ID, "antifox-sql-injection-testing", originalEnabled) })
	reopened, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	grants, err = reopened.AgentSkillNames(worker.ID)
	if err != nil || slices.Contains(grants, "antifox-sql-injection-testing") {
		t.Fatalf("startup restored revoked skill: %v %v", grants, err)
	}
}
