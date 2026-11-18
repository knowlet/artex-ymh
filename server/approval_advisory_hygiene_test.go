package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvisoryCommitHygieneForbiddenPaths(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{"server/jwt.key", "jwt.key"} {
		if st, err := os.Stat(filepath.Join(root, rel)); err == nil && !st.IsDir() {
			t.Fatalf("workspace contains forbidden %s — remove and never commit signing key files", rel)
		}
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	out, err := exec.Command("git", "-C", root, "ls-files", "server/jwt.key", "jwt.key", "web/out").Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) > 0 {
		t.Fatalf("forbidden paths tracked in git: %v", lines)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
