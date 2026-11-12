package skillcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/skillknowledge"
	"github.com/Autumn-27/artex/skillprovider"
	"github.com/Autumn-27/norma/skill"
)

func TestAntiFoxBundleNormaContract(t *testing.T) {
	provider := filepath.Join("..", "providers", "antifox")
	raw, err := os.ReadFile(filepath.Join(provider, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := skillprovider.ParseCatalog(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Skills) != 23 {
		t.Fatalf("got %d source skills", len(catalog.Skills))
	}
	root := t.TempDir()
	for _, entry := range catalog.Skills {
		name := skillprovider.SkillName(catalog, entry)
		if err := os.CopyFS(filepath.Join(root, name), os.DirFS(filepath.Join("..", "skills", name))); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := skill.LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 23 {
		t.Fatalf("loaded %d skills", len(reg.List()))
	}
	for _, entry := range catalog.Skills {
		name := skillprovider.SkillName(catalog, entry)
		t.Run(name, func(t *testing.T) {
			loaded, ok := reg.Get(name)
			if !ok || loaded.Name != filepath.Base(loaded.Dir) || loaded.License != "AGPL-3.0" || len(loaded.MCPs) != 0 {
				t.Fatalf("incompatible skill %+v", loaded)
			}
			original, err := os.ReadFile(filepath.Join(loaded.Dir, "references/source.md"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(original)
			if hex.EncodeToString(sum[:]) != entry.SourceSHA256 || int64(len(original)) != entry.SourceBytes {
				t.Fatal("source identity lost")
			}
			license, err := os.ReadFile(filepath.Join(loaded.Dir, "references/LICENSE"))
			if err != nil {
				t.Fatal(err)
			}
			sum = sha256.Sum256(license)
			if hex.EncodeToString(sum[:]) != catalog.Source.License.SHA256 {
				t.Fatal("license identity lost")
			}
			input, _ := json.Marshal(map[string]string{"name": name})
			result, err := reg.Tool().Call(t.Context(), input, nil)
			if err != nil || result.IsError || len(result.Extra) == 0 {
				t.Fatalf("Skill invocation failed: %v %+v", err, result)
			}
			guidance, _ := json.Marshal(result.Extra)
			if strings.Contains(string(guidance), "${SKILL_DIR}") || !strings.Contains(string(guidance), "references/source.md") {
				t.Fatal("reference substitution failed")
			}
			if name == "antifox-report-generation" && !strings.Contains(string(guidance), "finding_node_id") {
				t.Fatal("report bridge missing")
			}
		})
	}
	// Retained report templates and skeletons must survive a real skill load.
	for _, locale := range []string{"zh-TW", "zh-CN", "en-US"} {
		data, err := os.ReadFile(filepath.Join(root, "antifox-report-generation", "references/upstream/skeleton", locale, "methodology.json"))
		if err != nil || !json.Valid(data) {
			t.Fatalf("report resources %s: %v", locale, err)
		}
	}
}

func TestAntiFoxReusesIdenticalSkills(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "providers/antifox/overlap.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		Name   string
		SHA256 string
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected three shared skills, got %d", len(entries))
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join("..", "skills", entry.Name, "SKILL.md"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			t.Fatalf("shared skill changed: %s", entry.Name)
		}
		if _, err := os.Stat(filepath.Join("..", "skills", "antifox-"+entry.Name)); !os.IsNotExist(err) {
			t.Fatalf("duplicate shared skill: %s", entry.Name)
		}
	}
}

func TestAntiFoxRetrievalWithBundledLibrary(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatal(err)
	}
	idx := skillknowledge.New(reg)
	for query, want := range map[string]string{
		"SQL injection":  "antifox-sql-injection-testing",
		"IDOR BOLA":      "antifox-idor-testing",
		"容器映像":           "antifox-container-security-testing",
		"行動應用程式":         "antifox-mobile-app-security-testing",
		"LDAP injection": "antifox-ldap-injection-testing",
		"證據報告":           "antifox-report-generation",
	} {
		t.Run(query, func(t *testing.T) {
			result, err := idx.Search(t.Context(), query, "", 5)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, hit := range result.Hits {
				if hit.Skill == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing relevant skill %s for %s: %+v", want, query, result.Hits)
			}
		})
	}
}
