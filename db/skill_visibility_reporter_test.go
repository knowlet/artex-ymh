package db

import (
	"slices"
	"testing"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/skillprovider"
)

func TestReporterReportSkillVisibilityAfterAgentCreated(t *testing.T) {
	skillRoot := config.SkillDir()
	const skill = "antifox-report-generation"
	if !skillprovider.VerifyAntiFoxShippedSkill(skillRoot, skill) {
		t.Skip("bundled report skill not available in skill root")
	}
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	_ = d.DeleteAgent("reporter")

	lib := skillprovider.BundledAntiFoxLibraryID()
	if _, err := d.CreateAgent("reporter", "报告撰写", "visibility regression"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteAgent("reporter") })
	rep, err := d.GetAgentByKey("reporter")
	if err != nil || rep == nil {
		t.Fatal(err)
	}
	names, err := d.AgentSkillNamesInLibrary(rep.ID, lib)
	if err != nil || slices.Contains(names, skill) {
		t.Fatalf("grant must wait until deferred seed runs: %v %v", names, err)
	}

	if err := d.SeedBuiltinSkillVisibilityKeys(skillRoot, skill); err != nil {
		t.Fatal(err)
	}
	rep, err = d.GetAgentByKey("reporter")
	if err != nil || rep == nil {
		t.Fatal(err)
	}
	names, err = d.AgentSkillNamesInLibrary(rep.ID, lib)
	if err != nil || !slices.Contains(names, skill) {
		t.Fatalf("expected deferred grant for report skill: %v %v", names, err)
	}
	if err := d.ToggleSkillVisibilityInLibrary(rep.ID, skill, false, lib); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedBuiltinSkillVisibilityKeys(skillRoot, skill); err != nil {
		t.Fatal(err)
	}
	names, err = d.AgentSkillNamesInLibrary(rep.ID, lib)
	if err != nil || slices.Contains(names, skill) {
		t.Fatalf("explicit disable must survive deferred seed: %v %v", names, err)
	}
}
