package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/skillprovider"
)

type providerFailedWriter struct{ partial bool }

func (w providerFailedWriter) Write(b []byte) (int, error) {
	if w.partial && len(b) > 0 {
		return len(b) / 2, errors.New("synthetic output failure")
	}
	return 0, errors.New("synthetic output failure")
}

func TestProviderCLICommittedOutputFailure(t *testing.T) {
	requireProviderCLIFS(t)
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "no bytes", true: "partial report"}[partial], func(t *testing.T) {
			catalogPath, source, library := providerCLIFixture(t)
			var stderr bytes.Buffer
			args := []string{"import", "-catalog", catalogPath, "-source", source, "-dest", library, "-select", "notes"}
			code := providerCommand(context.Background(), args, providerFailedWriter{partial}, &stderr)
			if code != providerExitCommittedOutputFailed || !strings.Contains(stderr.String(), "committed=true") || !strings.Contains(stderr.String(), library) || !strings.Contains(stderr.String(), "provider status") {
				t.Fatalf("committed failure exit=%d stderr=%s", code, stderr.String())
			}
			catalog, err := skillprovider.LoadCatalogFile(catalogPath)
			if err != nil {
				t.Fatal(err)
			}
			report, err := skillprovider.Inspect(catalog, library)
			if err != nil || report.Skills[0].Imported != skillprovider.Verified {
				t.Fatalf("library not committed: %+v %v", report, err)
			}
			before, err := os.ReadFile(filepath.Join(library, skillprovider.ReceiptFilename))
			if err != nil {
				t.Fatal(err)
			}
			retry, out, retryErr := callProviderCLI(t, args...)
			after, err := os.ReadFile(filepath.Join(library, skillprovider.ReceiptFilename))
			if err != nil {
				t.Fatal(err)
			}
			if retry != 1 || len(out) != 0 || !strings.Contains(retryErr, "already exists") || !bytes.Equal(before, after) {
				t.Fatalf("retry changed committed library: exit=%d out=%s stderr=%s", retry, out, retryErr)
			}
		})
	}
}

func TestProviderCLIUncommittedAndReadOutputFailures(t *testing.T) {
	requireProviderCLIFS(t)
	catalog, source, library := providerCLIFixture(t)
	for _, args := range [][]string{
		{"catalog", "-catalog", catalog},
		{"status", "-catalog", catalog},
		{"import", "-catalog", catalog, "-source", source, "-dest", library, "-select", "unknown"},
	} {
		var stderr bytes.Buffer
		code := providerCommand(context.Background(), args, providerFailedWriter{}, &stderr)
		if code != 1 || strings.Contains(stderr.String(), "committed=true") {
			t.Fatalf("uncommitted/read failure exit=%d stderr=%s", code, stderr.String())
		}
	}
	if _, err := os.Lstat(library); !os.IsNotExist(err) {
		t.Fatalf("failed import created library: %v", err)
	}
}
