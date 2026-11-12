package db

import (
	"slices"
	"strings"
	"testing"

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
