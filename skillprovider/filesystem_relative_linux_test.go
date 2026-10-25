//go:build linux

package skillprovider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderRelativePathsUsePinnedWorkingDirectory(t *testing.T) {
	catalog, source, destination := importerFixture(t)
	root := filepath.Dir(source)
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	writeImporterFile(t, filepath.Join(root, "catalog.json"), raw)
	alias := filepath.Join(t.TempDir(), "logical-cwd")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	// Chdir/Setenv are deliberately serial: cwd and PWD are process-wide.
	t.Chdir(root)
	t.Setenv("PWD", alias)
	if cwd, err := os.Getwd(); err != nil || cwd != alias {
		t.Fatalf("symlink-form PWD precondition: cwd=%q err=%v", cwd, err)
	}
	loaded, err := LoadCatalogFile("./catalog.json")
	if err != nil {
		t.Fatalf("relative catalog under a logical cwd: %v", err)
	}
	if err := Import(context.Background(), loaded, "./source", "./imported", []string{"normal"}); err != nil {
		t.Fatalf("relative source/destination under a logical cwd: %v", err)
	}
	report, err := Inspect(loaded, "./imported")
	if err != nil || len(report.Skills) == 0 || report.Skills[0].Imported != Verified {
		t.Fatalf("relative library inspection failed: report=%+v err=%v", report, err)
	}
	if _, err := os.Stat(filepath.Join(destination, ReceiptFilename)); err != nil {
		t.Fatalf("library was not published in the real working directory: %v", err)
	}
	// Even when PWD names the current directory through a symlink, explicitly
	// supplying that symlink remains forbidden for absolute paths.
	if _, err := LoadCatalogFile(filepath.Join(alias, "catalog.json")); err == nil {
		t.Fatal("explicit absolute catalog symlink was followed")
	}
	if err := Import(context.Background(), loaded, filepath.Join(alias, "source"), "absolute-source-refused", []string{"normal"}); err == nil {
		t.Fatal("explicit absolute source symlink was followed")
	}
	if err := Import(context.Background(), loaded, "source", filepath.Join(alias, "absolute-target-refused"), []string{"normal"}); err == nil {
		t.Fatal("explicit absolute destination symlink was followed")
	}
	for _, target := range []string{"absolute-source-refused", "absolute-target-refused"} {
		if _, err := os.Lstat(filepath.Join(root, target)); !os.IsNotExist(err) {
			t.Fatalf("refused operation created %q: %v", target, err)
		}
	}
}

func TestProviderRelativePathsStillRejectSuppliedSymlinksAndTraversal(t *testing.T) {
	catalog, source, _ := importerFixture(t)
	root := filepath.Dir(source)
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	writeImporterFile(t, filepath.Join(root, "catalog.json"), raw)
	if err := os.Symlink("source", filepath.Join(root, "source-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(root, "parent-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("catalog.json", filepath.Join(root, "catalog-link.json")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	for _, filename := range []string{"catalog-link.json", "parent-link/catalog.json", "parent-link/../catalog.json"} {
		if _, err := LoadCatalogFile(filename); err == nil {
			t.Fatalf("unsafe relative catalog path accepted: %q", filename)
		}
	}
	for _, name := range []string{"source-link", "parent-link/source", "source/../source"} {
		if err := Import(context.Background(), catalog, name, "source-refused", []string{"normal"}); err == nil {
			t.Fatalf("unsafe relative source path accepted: %q", name)
		}
	}
	for _, name := range []string{"parent-link/destination-refused", "source/../destination-refused"} {
		if err := Import(context.Background(), catalog, "source", name, []string{"normal"}); err == nil {
			t.Fatalf("unsafe relative destination path accepted: %q", name)
		}
	}
	for _, name := range []string{"source-refused", "destination-refused"} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Fatalf("refused operation created %q: %v", name, err)
		}
	}
}
