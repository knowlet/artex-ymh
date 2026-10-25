package skillcheck

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

// Exercise ARTEX's actual dependency, rather than a parallel Markdown parser.
// Stage only the new skills so unrelated legacy parse failures cannot mask them.
func TestDiscoverySkillsLoadAndInvoke(t *testing.T) {
	root := t.TempDir()
	names := []string{"projectdiscovery-recon", "vulnerability-triage"}
	for _, name := range names {
		source := filepath.Join("..", "skills", name)
		if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			target := filepath.Join(root, name, rel)
			if entry.IsDir() {
				return os.MkdirAll(target, 0o700)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, content, 0o600)
		}); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := skill.LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.List()) != len(names) {
		t.Fatalf("loaded %d skills, want %d", len(registry.List()), len(names))
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			loaded, ok := registry.Get(name)
			if !ok || loaded.Name != name || loaded.Description == "" || loaded.Instructions == "" || loaded.Dir != filepath.Join(root, name) {
				t.Fatalf("incomplete load: %+v", loaded)
			}
			if len(loaded.MCPs) != 0 {
				t.Fatal("guidance must not unlock MCP tools")
			}
			ref := "commands.md"
			if name == "vulnerability-triage" {
				ref = "triage.md"
			}
			if _, err := os.Stat(filepath.Join(loaded.Dir, "references", ref)); err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(map[string]string{"name": name})
			result, err := registry.Tool().Call(context.Background(), input, nil)
			if err != nil || len(result.Extra) == 0 {
				t.Fatalf("invocation failed: %v, %+v", err, result)
			}
			guidance, err := json.Marshal(result.Extra)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(guidance), "${SKILL_DIR}") || !strings.Contains(string(guidance), "references/"+ref) {
				t.Fatalf("reference did not survive invocation: %s", guidance)
			}
		})
	}
}
