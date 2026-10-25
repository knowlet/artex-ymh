//go:build !linux

package skillprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// These are positive checks of the unsupported-platform contract, rather than
// passing filesystem-security tests because an unrelated backend error occurred.
func TestProviderUnsupportedFilesystemFailsClosed(t *testing.T) {
	c, source, destination := importerFixture(t)
	if err := c.Validate(); err != nil {
		t.Fatalf("fixture catalog must be valid: %v", err)
	}
	root := filepath.Dir(source)
	catalogPath := filepath.Join(root, "catalog.json")
	catalogJSON, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	writeImporterFile(t, catalogPath, catalogJSON)
	library := filepath.Join(root, "existing-library")
	writeImporterFile(t, filepath.Join(library, "user.txt"), []byte("Existing library content must remain unchanged.\n"))
	before := unsupportedFilesystemSnapshot(t, root)

	checks := []struct {
		name string
		run  func() error
	}{
		{"Import", func() error { return Import(context.Background(), c, source, destination, []string{"normal"}) }},
		// A slash-separated absolute path is accepted on Windows as well as Unix.
		// Native Windows backslashes are deliberately rejected by the path contract;
		// this case must reach the unsupported backend, not that earlier validator.
		{"LoadCatalogFile", func() error { _, err := LoadCatalogFile(filepath.ToSlash(catalogPath)); return err }},
		{"Inspect existing library", func() error { _, err := Inspect(c, library); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			err := check.run()
			if err == nil || !strings.Contains(err.Error(), unsupportedFS().Error()) {
				t.Fatalf("valid input must fail with unsupported-filesystem error: %v", err)
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("unsupported operation created destination: %v", err)
			}
			if after := unsupportedFilesystemSnapshot(t, root); !reflect.DeepEqual(before, after) {
				t.Fatalf("unsupported operation changed existing source/catalog/library state: before=%v after=%v", before, after)
			}
		})
	}
}

func unsupportedFilesystemSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if !entry.IsDir() {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("unexpected fixture file type: %s", path)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += " " + hashBytes(data)
		}
		snapshot[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
