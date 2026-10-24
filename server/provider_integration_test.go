package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/skillprovider"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/google/uuid"
)

// This test exercises the real importer, Norma Skill tool, PG visibility and
// usage ledger with original harmless text. It neither configures nor invokes
// MCPs, external tools, an LLM, or a task runner. CI requires PG rather than
// treating a missing service as successful integration coverage.
func TestProviderVisibilityAndMeteringPG(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("provider import integration requires the Linux filesystem backend")
	}
	requirePG := os.Getenv("ARTEX_PROVIDER_REQUIRE_PG") == "1"
	dsn, _, err := db.DSN()
	if err != nil {
		if requirePG {
			t.Fatalf("PostgreSQL required: %v", err)
		}
		t.Skipf("PostgreSQL not configured: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		if requirePG {
			t.Fatalf("PostgreSQL required: %v", err)
		}
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })

	source := t.TempDir()
	const sourcePath = "Skills/safe/hello/SKILL.md"
	const body = "# Benign fixture\n\nRecord a fictional blue square in a local notebook.\n\nSPDX-License-Identifier: MIT\n"
	const license = "SPDX-License-Identifier: MIT\nCopyright ARTEX test fixture authors\n"
	if err := os.MkdirAll(filepath.Join(source, "Skills", "safe", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{sourcePath: body, "LICENSE": license} {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(data string) string {
		sum := sha256.Sum256([]byte(data))
		return hex.EncodeToString(sum[:])
	}
	catalog := &skillprovider.Catalog{
		SchemaVersion: 1,
		Provider:      "fixture",
		Namespace:     "fixture",
		Source: skillprovider.Source{
			Repository: "https://example.invalid/provider",
			Revision:   strings.Repeat("a", 40),
			License: skillprovider.License{
				Path: "LICENSE", SHA256: digest(license), SPDX: "MIT",
			},
		},
		Skills: []skillprovider.Entry{{
			ID: "hello", Category: "safe", SourcePath: sourcePath,
			SourceSHA256: digest(body), SourceBytes: int64(len(body)), Format: "legacy",
			Description: "Benign fixture", Provenance: "verified", ImportPolicy: "allowed",
		}},
		Dependencies: []skillprovider.Dependency{},
	}
	// Import publishes a new library. It must not touch visibility or tool tables.
	library := filepath.Join(t.TempDir(), "library")
	if err := skillprovider.Import(context.Background(), catalog, source, library, []string{"hello"}); err != nil {
		t.Fatal(err)
	}
	const skillName = "fixture-hello"

	agentKey := "provider_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ag, err := pg.CreateAgent(agentKey, "Provider fixture", "Harmless integration test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pg.Exec(`DELETE FROM skill_usage WHERE agent_key=$1`, agentKey); err != nil {
			t.Errorf("clean usage: %v", err)
		}
		if err := pg.DeleteAgent(agentKey); err != nil {
			t.Errorf("clean agent: %v", err)
		}
	})

	originalAugment := agent.ToolAugment
	wireAgentAugment(pg, library, nil)
	t.Cleanup(func() { agent.ToolAugment = originalAugment })
	ri := agent.RunInfo{TaskID: 72341, ExplorationID: 72342, IntentID: 72343, SessionID: agentKey}
	ctx := agent.WithRunInfo(context.Background(), ri)
	assemble := func(t *testing.T, key string) []actool.CoreTool {
		t.Helper()
		extra, deferred, cleanup := agent.ToolAugment(ctx, key)
		if cleanup != nil {
			cleanup()
		}
		if len(deferred.Deferred) != 0 || len(deferred.GlobalNames) != 0 {
			t.Fatalf("provider fixture unexpectedly deferred executable tools: %+v", deferred)
		}
		return extra
	}
	if names, err := pg.AgentSkillNames(ag.ID); err != nil || len(names) != 0 {
		t.Fatalf("new agent visibility=%v, err=%v", names, err)
	}
	if extra := assemble(t, agentKey); len(extra) != 0 {
		t.Fatalf("imported skill became visible without binding: %v", extra)
	}
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	extra := assemble(t, agentKey)
	if len(extra) != 1 || extra[0].Name() != "Skill" {
		t.Fatalf("expected only the Skill meta-tool after binding, got %v", extra)
	}
	skillTool := extra[0]
	const args = "fictional context, never persisted as usage text"
	input, err := json.Marshal(map[string]string{"name": skillName, "args": args})
	if err != nil {
		t.Fatal(err)
	}
	result, err := skillTool.Call(ctx, input, nil)
	if err != nil || result.IsError {
		t.Fatalf("real Skill invocation: result=%+v, err=%v", result, err)
	}
	guidance, err := json.Marshal(result.Extra)
	if err != nil || !strings.Contains(string(guidance), "fictional blue square") {
		t.Fatalf("Norma did not emit imported instructions: %s, err=%v", guidance, err)
	}
	missing := "fixture-missing"
	missInput, err := json.Marshal(map[string]string{"name": missing})
	if err != nil {
		t.Fatal(err)
	}
	miss, err := skillTool.Call(ctx, missInput, nil)
	if err != nil || !miss.IsError || len(miss.Extra) != 0 {
		t.Fatalf("unknown skill must fail without guidance: result=%+v, err=%v", miss, err)
	}

	rows, err := pg.Query(`SELECT skill, task_id, exploration_id, intent_id, session_id, args_len, found
FROM skill_usage WHERE agent_key=$1 ORDER BY id`, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for i, expectedName := range []string{skillName, missing} {
		if !rows.Next() {
			t.Fatalf("usage row %d missing: %v", i, rows.Err())
		}
		var name, session string
		var taskID, explorationID, intentID int64
		var argsLen int
		var found bool
		if err := rows.Scan(&name, &taskID, &explorationID, &intentID, &session, &argsLen, &found); err != nil {
			t.Fatal(err)
		}
		expectedArgsLen := 0
		if i == 0 {
			expectedArgsLen = len(args)
		}
		if name != expectedName || taskID != ri.TaskID || explorationID != ri.ExplorationID ||
			intentID != ri.IntentID || session != ri.SessionID || argsLen != expectedArgsLen || found != (i == 0) {
			t.Fatalf("incorrect usage attribution: name=%q task=%d exploration=%d intent=%d session=%q args_len=%d found=%v",
				name, taskID, explorationID, intentID, session, argsLen, found)
		}
	}
	if rows.Next() || rows.Err() != nil {
		t.Fatalf("unexpected usage rows or query error: %v", rows.Err())
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	// Existing runs may retain loaded guidance. Revocation must take effect on
	// fresh assembly, which is the existing ARTEX visibility lifecycle contract.
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, false); err != nil {
		t.Fatal(err)
	}
	if extra := assemble(t, agentKey); len(extra) != 0 {
		t.Fatalf("revoked skill remained in a fresh run: %v", extra)
	}
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(library, skillName, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	if extra := assemble(t, agentKey); len(extra) != 0 {
		t.Fatalf("missing skill file became available: %v", extra)
	}
	if extra := assemble(t, agentKey+"_missing"); len(extra) != 0 {
		t.Fatalf("missing agent received tools: %v", extra)
	}

	t.Run("existing name grant follows configured library", func(t *testing.T) {
		// The prior out-of-band file removal left this name's grant in PG.
		// A new library path does not establish a new authorization identity.
		before, err := pg.AgentSkillNames(ag.ID)
		if err != nil || !slices.Equal(before, []string{skillName}) {
			t.Fatalf("expected retained same-name grant, got %v: %v", before, err)
		}
		replacement := filepath.Join(t.TempDir(), "replacement-library")
		if err := skillprovider.Import(ctx, catalog, source, replacement, []string{"hello"}); err != nil {
			t.Fatal(err)
		}
		after, err := pg.AgentSkillNames(ag.ID)
		if err != nil || !slices.Equal(before, after) {
			t.Fatalf("import changed visibility bindings: before=%v after=%v err=%v", before, after, err)
		}
		// This simulates configuring ARTEX to use the replacement library; the
		// importer itself neither switches libraries nor checks the runtime DB.
		wireAgentAugment(pg, replacement, nil)
		if extra := assemble(t, agentKey); len(extra) != 1 || extra[0].Name() != "Skill" {
			t.Fatalf("pre-existing same-name grant did not apply to replacement library: %v", extra)
		}

		// A different namespace has a different directory name. It is hidden
		// here because this test agent has no grant for that particular name.
		separateCatalog := *catalog
		separateCatalog.Namespace = "fixture-separate"
		separateLibrary := filepath.Join(t.TempDir(), "separate-library")
		if err := skillprovider.Import(ctx, &separateCatalog, source, separateLibrary, []string{"hello"}); err != nil {
			t.Fatal(err)
		}
		after, err = pg.AgentSkillNames(ag.ID)
		if err != nil || !slices.Equal(before, after) {
			t.Fatalf("distinct namespace import changed visibility bindings: before=%v after=%v err=%v", before, after, err)
		}
		wireAgentAugment(pg, separateLibrary, nil)
		if extra := assemble(t, agentKey); len(extra) != 0 {
			t.Fatalf("old name granted visibility to distinct namespace: %v", extra)
		}

		// Revoke the old name before configuring the replacement library.
		// Fresh runs then cannot see the imported skill at the reused name.
		if err := pg.ToggleSkillVisibility(ag.ID, skillName, false); err != nil {
			t.Fatal(err)
		}
		wireAgentAugment(pg, replacement, nil)
		if extra := assemble(t, agentKey); len(extra) != 0 {
			t.Fatalf("revoked name remained visible after library switch: %v", extra)
		}
	})
}
