package tools

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

// TestClaudeRedSkills checks the actual norma loader and all pinned source blobs.
func TestClaudeRedSkills(t *testing.T) {
	root := filepath.Join("..")
	lockRaw, err := os.ReadFile(filepath.Join(root, "packaging", "claude-red.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Source, Commit, Version, License, LicenseBlobSHA string
		Skills                                           []struct {
			Category, Name, SourcePath, BlobSHA string
			Size                                int
		}
	}
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Source != "https://github.com/SnailSploit/Claude-Red" || len(lock.Commit) != 40 ||
		lock.License != "MIT" || len(lock.Skills) != 79 {
		t.Fatalf("unexpected upstream lock metadata: source=%q commit=%q license=%q count=%d",
			lock.Source, lock.Commit, lock.License, len(lock.Skills))
	}

	license, err := os.ReadFile(filepath.Join(root, "third_party", "claude-red", "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if got := claudeRedBlobSHA(license); got != lock.LicenseBlobSHA {
		t.Fatalf("upstream MIT license changed: got %s want %s", got, lock.LicenseBlobSHA)
	}

	reg, err := skill.LoadDir(filepath.Join(root, "skills"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	cats := make(map[string]bool)
	for _, item := range lock.Skills {
		if item.Name == "" || strings.ContainsAny(item.Name, "/\\") ||
			item.SourcePath != "Skills/"+item.Category+"/"+item.Name+"/SKILL.md" ||
			item.BlobSHA == "" || seen[item.Name] {
			t.Fatalf("invalid or duplicate lock entry: %+v", item)
		}
		seen[item.Name] = true
		cats[item.Category] = true
		directory := filepath.Join(root, "skills", item.Name)
		reference, err := os.ReadFile(filepath.Join(directory, "references", "source.md"))
		if err != nil {
			t.Fatalf("%s: %v", item.Name, err)
		}
		// Images and release archives distribute skills/ independently of the
		// repository's third_party/. Keep the original notice with each source.
		notice, err := os.ReadFile(filepath.Join(directory, "references", "LICENSE"))
		if err != nil {
			t.Fatalf("%s: distributed reference lacks MIT notice: %v", item.Name, err)
		}
		if got := claudeRedBlobSHA(notice); got != lock.LicenseBlobSHA {
			t.Errorf("%s: distributed MIT notice changed, got %s expected %s", item.Name, got, lock.LicenseBlobSHA)
		}
		if len(reference) != item.Size {
			t.Errorf("%s: %d bytes, expected %d", item.Name, len(reference), item.Size)
		}
		if got := claudeRedBlobSHA(reference); got != item.BlobSHA {
			t.Errorf("%s: source blob changed, got %s expected %s", item.Name, got, item.BlobSHA)
		}
		loaded, ok := reg.Get(item.Name)
		if !ok {
			t.Errorf("%s: not discoverable by norma skill.LoadDir", item.Name)
			continue
		}
		if loaded.Name != item.Name || loaded.Description == "" || loaded.License != "MIT" ||
			filepath.Base(loaded.Dir) != item.Name {
			t.Errorf("%s: bad ARTEX skill metadata: %+v", item.Name, loaded)
		}
		if !strings.Contains(loaded.Instructions, "$"+"{SKILL_DIR}/references/source.md") {
			t.Errorf("%s: SKILL.md does not link the original reference", item.Name)
		}
		if len(loaded.MCPs) != 0 {
			t.Errorf("%s: should not implicitly unlock MCP servers", item.Name)
		}
	}
	if len(cats) != 23 {
		t.Errorf("categories: got %d, expected 23", len(cats))
	}
}

func claudeRedBlobSHA(content []byte) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(content))
	_, _ = h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}
