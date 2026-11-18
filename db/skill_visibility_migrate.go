package db

import (
	"github.com/Autumn-27/artex/skillprovider"
)

// migrateAntiFoxSkillLibraryIDs moves pre-scoped antifox grants from the legacy
// empty library_id into the bundled identity so revocations and startup seeding
// apply to a single row per (agent, skill).
func (d *DB) migrateAntiFoxSkillLibraryIDs() error {
	bundled := skillprovider.BundledAntiFoxLibraryID()
	if _, err := d.Exec(`
UPDATE agent_skill_visibility b
SET enabled = b.enabled AND l.enabled
FROM agent_skill_visibility l
WHERE l.skill_name LIKE 'antifox-%' AND l.library_id = ''
  AND b.agent_id = l.agent_id AND b.skill_name = l.skill_name
  AND b.library_id = $1`, bundled); err != nil {
		return err
	}
	if _, err := d.Exec(`
DELETE FROM agent_skill_visibility l
USING agent_skill_visibility b
WHERE l.skill_name LIKE 'antifox-%' AND l.library_id = ''
  AND b.agent_id = l.agent_id AND b.skill_name = l.skill_name
  AND b.library_id = $1`, bundled); err != nil {
		return err
	}
	if _, err := d.Exec(`
UPDATE agent_skill_visibility SET library_id = $1
WHERE skill_name LIKE 'antifox-%' AND library_id = ''`, bundled); err != nil {
		return err
	}
	// Drop any legacy rows that could not be merged (duplicate bundled row already present).
	_, err := d.Exec(`DELETE FROM agent_skill_visibility WHERE skill_name LIKE 'antifox-%' AND library_id = ''`)
	return err
}
