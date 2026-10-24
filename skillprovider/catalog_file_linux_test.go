//go:build linux

package skillprovider

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
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
