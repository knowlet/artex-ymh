package db

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/skillprovider"
)

func shippedSkillLibraryID(skillRoot, skillName string) string {
	return skillprovider.ShippedSkillLibraryID(skillRoot, skillName)
}

func builtinSkillDirPresent(skillRoot, name string) bool {
	info, err := os.Stat(filepath.Join(skillRoot, name))
	return err == nil && info.IsDir()
}

// IsShippedBuiltinSkill reports whether skillName is part of the shipped default map.
func IsShippedBuiltinSkill(skillName string) bool {
	_, ok := builtinSkillVisibility[skillName]
	return ok
}

// AgentSkillNamesForRuntime merges visibility grants for a legacy skill root and any
// bundled provider libraries co-located in that directory.
func (d *DB) AgentSkillNamesForRuntime(agentID int64, skillRoot string) ([]string, error) {
	libraries, err := skillprovider.BundledSkillLibraryIDsForRuntime(skillRoot)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, lib := range libraries {
		names, err := d.AgentSkillNamesInLibrary(agentID, lib)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if lib == "" && strings.HasPrefix(n, "antifox-") && shippedSkillLibraryID(skillRoot, n) != "" {
				continue
			}
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out, nil
}

func visibilityLibraryForSkill(skillRoot, skillName string) (string, error) {
	return skillprovider.SkillVisibilityLibraryID(skillRoot, skillName)
}

// SetAgentSkillVisibilityRuntime replaces skill visibility for one agent across every
// library identity that applies to the configured skill root.
func (d *DB) SetAgentSkillVisibilityRuntime(agentID int64, skillRoot string, names []string) error {
	libraries, err := skillprovider.BundledSkillLibraryIDsForRuntime(skillRoot)
	if err != nil {
		return err
	}
	byLib := make(map[string][]string, len(libraries))
	for _, name := range names {
		lib, err := visibilityLibraryForSkill(skillRoot, name)
		if err != nil {
			return err
		}
		byLib[lib] = append(byLib[lib], name)
	}
	for _, lib := range libraries {
		if err := d.SetAgentSkillVisibilityInLibrary(agentID, byLib[lib], lib); err != nil {
			return err
		}
	}
	return nil
}
