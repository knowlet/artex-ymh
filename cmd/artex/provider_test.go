package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/skillprovider"
)

func providerCLIFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	const sourcePath = "Skills/stationery/notes/SKILL.md"
	const body = "# Synthetic notes\n\nDescribe an imaginary yellow notebook.\nCopyright: fixture authors.\n"
	const license = "MIT License\nCopyright: synthetic fixture authors.\n"
	if err := os.MkdirAll(filepath.Join(source, "Skills", "stationery", "notes"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{sourcePath: body, "LICENSE": license} {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hash := func(data string) string {
		sum := sha256.Sum256([]byte(data))
		return hex.EncodeToString(sum[:])
	}
	catalog := skillprovider.Catalog{
		SchemaVersion: 1, Provider: "fixture", Namespace: "fixture",
		Source: skillprovider.Source{
			Repository: "https://example.invalid/provider", Revision: strings.Repeat("a", 40),
			License: skillprovider.License{Path: "LICENSE", SHA256: hash(license), SPDX: "MIT"},
		},
		Skills: []skillprovider.Entry{{
			ID: "notes", Category: "stationery", SourcePath: sourcePath, SourceSHA256: hash(body),
			SourceBytes: int64(len(body)), Format: "legacy", Description: "Harmless notebook fixture.",
			Provenance: "verified", ImportPolicy: "allowed", Dependencies: []string{},
		}},
		Dependencies: []skillprovider.Dependency{},
	}
	data, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(root, "catalog.json")
	if err := os.WriteFile(catalogPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return catalogPath, source, filepath.Join(root, "library")
}

func callProviderCLI(t *testing.T, args ...string) (int, []byte, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := providerCommand(context.Background(), args, &out, &errOut)
	return code, out.Bytes(), errOut.String()
}

func TestProviderCLICatalogAndStatusRemainMetadataOnly(t *testing.T) {
	catalogPath, err := filepath.Abs(filepath.Join("..", "..", "providers", "claude-red", "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, out, stderr := callProviderCLI(t, "catalog", "-catalog", catalogPath)
	if code != 0 {
		t.Fatalf("catalog exit=%d: %s", code, stderr)
	}
	catalog, err := skillprovider.ParseCatalog(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Provider != "claude-red" || len(catalog.Skills) != 79 || catalog.Source.Revision != "a8de813edc9f66f60d44cfe42d47750e89d9930b" {
		t.Fatalf("unexpected pinned catalog: provider=%s revision=%s count=%d", catalog.Provider, catalog.Source.Revision, len(catalog.Skills))
	}
	for _, entry := range catalog.Skills {
		if entry.Provenance != "provenance-unverified" || entry.ImportPolicy != "metadata-only" {
			t.Fatalf("upstream entry treated as approved content: %+v", entry)
		}
	}
	library := filepath.Join(t.TempDir(), "absent-library")
	code, out, stderr = callProviderCLI(t, "status", "-catalog", catalogPath, "-library", library)
	if code != 0 {
		t.Fatalf("status exit=%d: %s", code, stderr)
	}
	var report skillprovider.ReadinessReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Skills) != 79 {
		t.Fatalf("status reported %d entries", len(report.Skills))
	}
	for _, entry := range report.Skills {
		if !entry.Metadata || entry.Imported != skillprovider.Missing || entry.AgentVisible != skillprovider.Unknown {
			t.Fatalf("catalog implies import or visibility: %+v", entry)
		}
		for _, dependency := range entry.Dependencies {
			if !dependency.Metadata || dependency.Registered != skillprovider.Unknown ||
				dependency.BinaryHashVerified != skillprovider.Unknown || dependency.RuntimeVerified != skillprovider.Unknown {
				t.Fatalf("catalog implies tool execution readiness: %+v", dependency)
			}
		}
	}
	if _, err := os.Lstat(library); !os.IsNotExist(err) {
		t.Fatalf("catalog/status created a library: %v", err)
	}
}

func TestProviderCLIExplicitImportAndStatus(t *testing.T) {
	catalogPath, source, library := providerCLIFixture(t)
	code, out, stderr := callProviderCLI(t, "import", "-catalog", catalogPath, "-source", source, "-dest", library, "-select", "notes")
	if code != 0 {
		t.Fatalf("import exit=%d: %s", code, stderr)
	}
	var imported struct {
		Library              string   `json:"library"`
		ImportedIDs          []string `json:"imported_ids"`
		AgentBindingsCreated bool     `json:"agent_bindings_created"`
		RuntimeVerified      bool     `json:"runtime_verified"`
	}
	if err := json.Unmarshal(out, &imported); err != nil {
		t.Fatal(err)
	}
	if imported.Library != library || len(imported.ImportedIDs) != 1 || imported.ImportedIDs[0] != "notes" || imported.AgentBindingsCreated || imported.RuntimeVerified {
		t.Fatalf("unexpected import report: %+v", imported)
	}
	code, out, stderr = callProviderCLI(t, "status", "-catalog", catalogPath, "-library", library)
	if code != 0 {
		t.Fatalf("status exit=%d: %s", code, stderr)
	}
	var report skillprovider.ReadinessReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Skills) != 1 || report.Skills[0].Imported != skillprovider.Verified || report.Skills[0].AgentVisible != skillprovider.Unknown {
		t.Fatalf("status conflated import and visibility: %+v", report)
	}
}

func TestProviderCLIRefusesImplicitAndUnverifiedImport(t *testing.T) {
	t.Run("no selection", func(t *testing.T) {
		catalogPath, source, library := providerCLIFixture(t)
		code, _, stderr := callProviderCLI(t, "import", "-catalog", catalogPath, "-source", source, "-dest", library)
		if code != 2 || !strings.Contains(stderr, "explicit -select") {
			t.Fatalf("implicit import exit=%d: %s", code, stderr)
		}
		if _, err := os.Lstat(library); !os.IsNotExist(err) {
			t.Fatalf("implicit import created destination: %v", err)
		}
	})
	t.Run("unverified provenance", func(t *testing.T) {
		catalogPath, source, library := providerCLIFixture(t)
		data, err := os.ReadFile(catalogPath)
		if err != nil {
			t.Fatal(err)
		}
		var catalog skillprovider.Catalog
		if err := json.Unmarshal(data, &catalog); err != nil {
			t.Fatal(err)
		}
		catalog.Skills[0].Provenance = "provenance-unverified"
		catalog.Skills[0].ImportPolicy = "metadata-only"
		data, err = json.Marshal(catalog)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(catalogPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := callProviderCLI(t, "import", "-catalog", catalogPath, "-source", source, "-dest", library, "-select", "notes")
		if code != 1 || stderr == "" {
			t.Fatalf("unverified import exit=%d: %s", code, stderr)
		}
		if _, err := os.Lstat(library); !os.IsNotExist(err) {
			t.Fatalf("unverified import created destination: %v", err)
		}
	})
}

func TestProviderCLIMissingOrInvalidInputs(t *testing.T) {
	catalogPath, _, _ := providerCLIFixture(t)
	for _, args := range [][]string{
		nil, {"unknown"}, {"status"}, {"status", "-catalog", catalogPath, "unexpected"},
		{"status", "-catalog", filepath.Join(t.TempDir(), "missing.json")},
		{"status", "-unsupported"},
	} {
		code, out, stderr := callProviderCLI(t, args...)
		if code == 0 || len(out) != 0 || stderr == "" {
			t.Fatalf("invalid CLI %q exit=%d stdout=%s stderr=%s", args, code, out, stderr)
		}
	}
	if err := os.WriteFile(catalogPath, []byte(`{"schema_version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := callProviderCLI(t, "catalog", "-catalog", catalogPath); code != 1 || len(out) != 0 || stderr == "" {
		t.Fatalf("unknown schema exit=%d stdout=%s stderr=%s", code, out, stderr)
	}
}

// This checks direct production imports and calls; it supplements the real
// filesystem tests and is not a claim of syscall tracing of all dependencies.
func TestProviderProductionCodeHasNoProcessOrNetworkAPIs(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "skillprovider", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "provider.go")
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		imports := map[string]string{}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if path == "os/exec" || path == "plugin" || path == "net" ||
				(strings.HasPrefix(path, "net/") && path != "net/url") {
				t.Errorf("%s imports process/network package %s", name, path)
			}
			alias := filepath.Base(path)
			if imported.Name != nil {
				alias = imported.Name.Name
				if alias == "." || alias == "_" {
					t.Errorf("%s has opaque import %s", name, path)
				}
			}
			imports[alias] = path
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			alias, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			path := imports[alias.Name]
			if path != "os" && path != "syscall" && path != "golang.org/x/sys/unix" {
				return true
			}
			switch selector.Sel.Name {
			case "Exec", "ForkExec", "StartProcess", "SYS_EXECVE", "SYS_EXECVEAT", "SYS_FORK", "SYS_VFORK", "SYS_CLONE", "SYS_CLONE3":
				t.Errorf("%s references process API %s.%s", name, alias.Name, selector.Sel.Name)
			}
			return true
		})
	}
	if checked < 4 {
		t.Fatalf("only checked %d files; provider production code missing", checked)
	}
}

func TestProviderCLICatalogSymlinksRefused(t *testing.T) {
	catalogPath, _, _ := providerCLIFixture(t)
	link := filepath.Join(t.TempDir(), "linked-catalog.json")
	if err := os.Symlink(catalogPath, link); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := callProviderCLI(t, "catalog", "-catalog", link); code == 0 {
		t.Fatal("symlink catalog accepted")
	}
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(filepath.Dir(catalogPath), parent); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := callProviderCLI(t, "catalog", "-catalog", filepath.Join(parent, filepath.Base(catalogPath))); code == 0 {
		t.Fatal("symlink catalog parent accepted")
	}
}
