package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
	libraryID, err := skillprovider.LibraryIdentity(library)
	if err != nil || libraryID == "" {
		t.Fatalf("import identity=%q: %v", libraryID, err)
	}

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

	api := &Server{m: &Manager{pg: pg}, skillDir: library}
	grant := func(t *testing.T, on bool) {
		t.Helper()
		body := `{"agent_id":"` + strconv.FormatInt(ag.ID, 10) + `","skill_name":"` + skillName + `","visible":` + strconv.FormatBool(on) + `}`
		w := httptest.NewRecorder()
		api.pgToggleSkillVisibility(w, httptest.NewRequest(http.MethodPost, "/api/visibility/skill/toggle", strings.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("grant response=%d: %s", w.Code, w.Body.String())
		}
	}
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
	// A legacy same-name grant must not authorize this provider library.
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	if extra := assemble(t, agentKey); len(extra) != 0 {
		t.Fatalf("legacy grant authorized imported skill: %v", extra)
	}
	grant(t, true)
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
	grant(t, false)
	if extra := assemble(t, agentKey); len(extra) != 0 {
		t.Fatalf("revoked skill remained in a fresh run: %v", extra)
	}
	grant(t, true)
	if err := os.Remove(filepath.Join(library, skillName, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	if extra := assemble(t, agentKey); len(extra) != 0 {
		t.Fatalf("missing skill file became available: %v", extra)
	}
	if extra := assemble(t, agentKey+"_missing"); len(extra) != 0 {
		t.Fatalf("missing agent received tools: %v", extra)
	}

	t.Run("same-name library requires a fresh grant", func(t *testing.T) {
		before, err := pg.AgentSkillNamesInLibrary(ag.ID, libraryID)
		if err != nil || !slices.Equal(before, []string{skillName}) {
			t.Fatalf("expected retained scoped grant, got %v: %v", before, err)
		}
		replacement := filepath.Join(t.TempDir(), "replacement-library")
		if err := skillprovider.Import(ctx, catalog, source, replacement, []string{"hello"}); err != nil {
			t.Fatal(err)
		}
		replacementID, err := skillprovider.LibraryIdentity(replacement)
		if err != nil || replacementID == libraryID || replacementID == "" {
			t.Fatalf("new import reused identity %q: %v", replacementID, err)
		}
		after, err := pg.AgentSkillNamesInLibrary(ag.ID, libraryID)
		if err != nil || !slices.Equal(before, after) {
			t.Fatalf("import changed visibility bindings: before=%v after=%v err=%v", before, after, err)
		}
		wireAgentAugment(pg, replacement, nil)
		api.skillDir = replacement
		if extra := assemble(t, agentKey); len(extra) != 0 {
			t.Fatalf("same-name grant leaked into replacement library: %v", extra)
		}
		// Both sides of visibility report only the currently configured library.
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/visibility/skill/"+skillName, nil)
		r.SetPathValue("name", skillName)
		api.pgSkillVisibility(w, r)
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), strconv.FormatInt(ag.ID, 10)) {
			t.Fatalf("old binding appeared in replacement visibility: %d %s", w.Code, w.Body.String())
		}
		grant(t, true)
		if extra := assemble(t, agentKey); len(extra) != 1 || extra[0].Name() != "Skill" {
			t.Fatalf("fresh explicit library grant did not apply: %v", extra)
		}
		if names, err := pg.AgentSkillNamesInLibrary(ag.ID, libraryID); err != nil || len(names) != 0 {
			t.Fatalf("regrant retained old library binding: %v %v", names, err)
		}
		grant(t, false)
		if extra := assemble(t, agentKey); len(extra) != 0 {
			t.Fatalf("revoked scoped skill remained available: %v", extra)
		}
		// Bulk visibility writes must also bind to the current library.
		w = httptest.NewRecorder()
		r = httptest.NewRequest(http.MethodPut, "/api/agents/"+agentKey+"/visibility", strings.NewReader(`{"mcp":[],"skill":["`+skillName+`"]}`))
		r.SetPathValue("key", agentKey)
		api.pgSetAgentVisibility(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("bulk grant response=%d: %s", w.Code, w.Body.String())
		}
		if extra := assemble(t, agentKey); len(extra) != 1 {
			t.Fatalf("bulk scoped grant was not loaded: %v", extra)
		}
		// Accidental receipt loss must not reactivate a pre-provider name grant.
		if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
			t.Fatal(err)
		}
		receiptPath := filepath.Join(replacement, skillprovider.ReceiptFilename)
		receiptBytes, err := os.ReadFile(receiptPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(receiptPath); err != nil {
			t.Fatal(err)
		}
		if extra := assemble(t, agentKey); len(extra) != 0 {
			t.Fatalf("receipt loss reactivated legacy grant: %v", extra)
		}
		if err := os.WriteFile(receiptPath, receiptBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		// A malformed receipt must fail closed at both runtime and grant controls.
		if err := os.WriteFile(filepath.Join(replacement, skillprovider.ReceiptFilename), []byte(`{"schema_version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if extra := assemble(t, agentKey); len(extra) != 0 {
			t.Fatalf("invalid receipt authorized guidance: %v", extra)
		}
		w = httptest.NewRecorder()
		api.pgToggleSkillVisibility(w, httptest.NewRequest(http.MethodPost, "/api/visibility/skill/toggle", strings.NewReader(`{"agent_id":"`+strconv.FormatInt(ag.ID, 10)+`","skill_name":"`+skillName+`","visible":true}`)))
		if w.Code != http.StatusConflict {
			t.Fatalf("invalid receipt grant response=%d: %s", w.Code, w.Body.String())
		}
	})
}
