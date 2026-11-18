package db

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/skillprovider"
	"github.com/google/uuid"
)

func TestBuiltinSkillRevocationSurvivesStartup(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	worker, err := d.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatal("worker missing", err)
	}
	original, err := d.AgentSkillNames(worker.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.SetAgentSkillVisibility(worker.ID, original); err != nil {
			t.Error(err)
		}
	})
	assertRevoked := func() {
		t.Helper()
		reopened, err := Open(testDSN(t))
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		names, err := reopened.AgentSkillNames(worker.ID)
		if err != nil || slices.Contains(names, "api-recon") {
			t.Fatalf("startup re-enabled revoked built-in: %v %v", names, err)
		}
	}
	if err := d.ToggleSkillVisibility(worker.ID, "api-recon", false); err != nil {
		t.Fatal(err)
	}
	assertRevoked()
	if err := d.ToggleSkillVisibility(worker.ID, "api-recon", true); err != nil {
		t.Fatal(err)
	}
	selected := slices.DeleteFunc(slices.Clone(original), func(s string) bool { return s == "api-recon" })
	if err := d.SetAgentSkillVisibility(worker.ID, selected); err != nil {
		t.Fatal(err)
	}
	assertRevoked()
}

func TestSkillRevocationDoesNotTouchAnotherLibrary(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	a, err := d.CreateAgent("scope_"+strings.ReplaceAll(uuid.NewString(), "-", ""), "Scope fixture", "Harmless test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteAgent(a.Key) })
	if err := d.ToggleSkillVisibilityInLibrary(a.ID, "same-name", true, "library-a"); err != nil {
		t.Fatal(err)
	}
	for _, revoke := range []func() error{
		func() error { return d.ToggleSkillVisibilityInLibrary(a.ID, "same-name", false, "library-b") },
		func() error { return d.SetAgentSkillVisibilityInLibrary(a.ID, nil, "library-b") },
	} {
		if err := revoke(); err != nil {
			t.Fatal(err)
		}
		names, err := d.AgentSkillNamesInLibrary(a.ID, "library-a")
		if err != nil || !slices.Contains(names, "same-name") {
			t.Fatalf("other-library revocation changed a grant: %v %v", names, err)
		}
	}
	if err := d.ToggleSkillVisibilityInLibrary(a.ID, "same-name", false, "library-a"); err != nil {
		t.Fatal(err)
	}
	names, err := d.AgentSkillNamesInLibrary(a.ID, "library-a")
	if err != nil || len(names) != 0 {
		t.Fatalf("revocation failed: %v %v", names, err)
	}
	if err := d.ToggleSkillVisibilityInLibrary(a.ID, "same-name", true, "library-b"); err != nil {
		t.Fatal(err)
	}
	names, err = d.AgentSkillNamesInLibrary(a.ID, "library-b")
	if err != nil || !slices.Contains(names, "same-name") {
		t.Fatalf("new explicit grant failed: %v %v", names, err)
	}
}

func TestSkillCrossLibraryRevokeGrantRemoveReopen(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	a, err := d.CreateAgent("xlib_"+strings.ReplaceAll(uuid.NewString(), "-", ""), "fixture", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteAgent(a.Key) })
	const skill = "same-name"
	if err := d.ToggleSkillVisibilityInLibrary(a.ID, skill, true, "library-a"); err != nil {
		t.Fatal(err)
	}
	if err := d.ToggleSkillVisibilityInLibrary(a.ID, skill, false, "library-a"); err != nil {
		t.Fatal(err)
	}
	if err := d.ToggleSkillVisibilityInLibrary(a.ID, skill, true, "library-b"); err != nil {
		t.Fatal(err)
	}
	names, err := d.AgentSkillNamesInLibrary(a.ID, "library-a")
	if err != nil || len(names) != 0 {
		t.Fatalf("revoke in A must survive grant in B: %v %v", names, err)
	}
	if err := d.RemoveSkillLibraryGrants(skill, "library-b"); err != nil {
		t.Fatal(err)
	}
	if err := d.ToggleSkillVisibilityInLibrary(a.ID, skill, false, "library-a"); err != nil {
		t.Fatal(err)
	}
	names, err = d.AgentSkillNamesInLibrary(a.ID, "library-a")
	if err != nil || len(names) != 0 {
		t.Fatalf("revoke after B removal failed: %v %v", names, err)
	}
	reopened, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if names, err := reopened.AgentSkillNamesInLibrary(a.ID, "library-a"); err != nil || slices.Contains(names, skill) {
		t.Fatalf("startup re-enabled revoked skill: %v %v", names, err)
	}
}

func TestSeedSkipsUnverifiedAntiFoxDirectory(t *testing.T) {
	tmp := t.TempDir()
	skillRoot := filepath.Join(tmp, "skills")
	providerRoot := filepath.Join(tmp, "providers", "antifox")
	if err := os.MkdirAll(filepath.Join(skillRoot, "antifox-sql-injection-testing", "references"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillRoot, "antifox-sql-injection-testing", "references", "source.md"), []byte("tampered-local"), 0o644); err != nil {
		t.Fatal(err)
	}
	catalogSrc, err := os.ReadFile(filepath.Join("..", "providers", "antifox", "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(providerRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(providerRoot, "catalog.json"), catalogSrc, 0o644); err != nil {
		t.Fatal(err)
	}
	skillprovider.ResetBundledAntiFoxCatalogForTest()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.seedBuiltinSkillVisibility(skillRoot); err != nil {
		t.Fatal(err)
	}
	planner, err := d.GetAgentByKey("planner")
	if err != nil || planner == nil {
		t.Fatal(err)
	}
	names, err := d.AgentSkillNamesInLibrary(planner.ID, skillprovider.BundledAntiFoxLibraryID())
	if err != nil || slices.Contains(names, "antifox-sql-injection-testing") {
		t.Fatalf("unverified local dir must not receive default grant: %v %v", names, err)
	}
}

func TestDeleteSkillPreservesShippedRevocation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	worker, err := d.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatal(err)
	}
	const name = "api-recon"
	lib := ""
	if err := d.ToggleSkillVisibility(worker.ID, name, false); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteSkillVisibilityInLibrary(name, lib, true); err != nil {
		t.Fatal(err)
	}
	names, err := d.AgentSkillNames(worker.ID)
	if err != nil || slices.Contains(names, name) {
		t.Fatalf("shipped delete must leave revocation: %v %v", names, err)
	}
	reopened, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if names, err := reopened.AgentSkillNames(worker.ID); err != nil || slices.Contains(names, name) {
		t.Fatalf("startup resurrected revoked shipped skill: %v %v", names, err)
	}
}
