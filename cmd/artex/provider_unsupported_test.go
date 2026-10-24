//go:build !linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderCLIUnsupportedFilesystemFailsClosed(t *testing.T) {
	catalog, source, library := providerCLIFixture(t)
	catalog = filepath.ToSlash(catalog)
	original, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"catalog", "-catalog", catalog},
		{"status", "-catalog", catalog, "-library", source},
		{"import", "-catalog", catalog, "-source", source, "-dest", library, "-select", "notes"},
		{"recover", "-stage", filepath.Join(filepath.Dir(library), ".provider-stage-"+strings.Repeat("a", 32))},
	} {
		code, out, stderr := callProviderCLI(t, args...)
		if code != 1 || len(out) != 0 || !strings.Contains(stderr, "require Linux") {
			t.Fatalf("unsupported action accepted: %v exit=%d out=%s stderr=%s", args, code, out, stderr)
		}
	}
	after, err := os.ReadFile(catalog)
	if err != nil || string(after) != string(original) {
		t.Fatal("unsupported commands changed catalog")
	}
	if _, err := os.Lstat(library); !os.IsNotExist(err) {
		t.Fatalf("unsupported command created library: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(library))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".provider-stage-") {
			t.Fatal("unsupported command created staging")
		}
	}
}
