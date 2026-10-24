//go:build linux

package skillprovider

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderCatalogFileRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalogFile(path); err == nil {
		t.Fatal("FIFO catalog accepted")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("catalog file was changed")
	}
}

func TestProviderCatalogNestingBound(t *testing.T) {
	if _, err := ParseCatalog(strings.NewReader(strings.Repeat("[", 64) + strings.Repeat("]", 64))); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep JSON not rejected by nesting limit: %v", err)
	}
}
