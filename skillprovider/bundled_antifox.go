package skillprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// BundledAntiFoxLibraryID scopes default grants and visibility for hash-verified
// shipped AntiFox skills. Same-named directories that fail verification require an
// explicit grant under another library identity.
func BundledAntiFoxLibraryID() string {
	return "bundled:antifox:070f798bf590667bc2a0a13c687dd87d8a4413bf"
}

var (
	antiFoxCatalogOnce sync.Once
	antiFoxCatalog     *Catalog
	antiFoxCatalogErr  error
	antiFoxBySkillName map[string]Entry
)

// ResetBundledAntiFoxCatalogForTest clears the catalog cache (tests only).
func ResetBundledAntiFoxCatalogForTest() {
	antiFoxCatalogOnce = sync.Once{}
	antiFoxCatalog = nil
	antiFoxCatalogErr = nil
	antiFoxBySkillName = nil
}

func loadAntiFoxCatalog(skillRoot string) (*Catalog, map[string]Entry, error) {
	antiFoxCatalogOnce.Do(func() {
		path := filepath.Join(filepath.Dir(skillRoot), "providers", "antifox", "catalog.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			antiFoxCatalogErr = fmt.Errorf("antifox catalog: %w", err)
			return
		}
		c, err := ParseCatalog(strings.NewReader(string(raw)))
		if err != nil {
			antiFoxCatalogErr = err
			return
		}
		antiFoxCatalog = c
		if c.Source.Revision != "070f798bf590667bc2a0a13c687dd87d8a4413bf" {
			antiFoxCatalogErr = fmt.Errorf("unexpected antifox revision %q", c.Source.Revision)
			return
		}
		antiFoxBySkillName = make(map[string]Entry, len(c.Skills))
		for _, e := range c.Skills {
			antiFoxBySkillName[SkillName(c, e)] = e
		}
	})
	if antiFoxCatalogErr != nil {
		return nil, nil, antiFoxCatalogErr
	}
	return antiFoxCatalog, antiFoxBySkillName, nil
}

// VerifyAntiFoxShippedSkill reports whether skillRoot/dirName matches the pinned
// bundled adapter (references/source.md identity from catalog.json).
func VerifyAntiFoxShippedSkill(skillRoot, dirName string) bool {
	if !strings.HasPrefix(dirName, "antifox-") {
		return false
	}
	_, byName, err := loadAntiFoxCatalog(skillRoot)
	if err != nil {
		return false
	}
	entry, ok := byName[dirName]
	if !ok {
		return false
	}
	data, err := os.ReadFile(filepath.Join(skillRoot, dirName, "references", "source.md"))
	if err != nil {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == entry.SourceSHA256 && int64(len(data)) == entry.SourceBytes
}

// ShippedSkillLibraryID returns the library_id used for default grants.
func ShippedSkillLibraryID(skillRoot, skillName string) string {
	if strings.HasPrefix(skillName, "antifox-") && VerifyAntiFoxShippedSkill(skillRoot, skillName) {
		return BundledAntiFoxLibraryID()
	}
	return ""
}

// BundledSkillLibraryIDsForRuntime returns library_id values whose grants apply when
// loading skills from a legacy (no provider receipt) skill root.
func BundledSkillLibraryIDsForRuntime(skillRoot string) ([]string, error) {
	id, err := LibraryIdentity(skillRoot)
	if err != nil {
		return nil, err
	}
	if id != "" {
		return []string{id}, nil
	}
	return []string{"", BundledAntiFoxLibraryID()}, nil
}
