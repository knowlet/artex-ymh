package skillprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

const syntheticLicense = "MIT License\nCopyright (c) 2026 synthetic ARTEX fixture authors\nPermission notice retained for harmless test content.\n"
const syntheticBody = "\n# Harmless inventory\n\nList local fictional stationery; do not run commands.\nCopyright: synthetic fixture authors.\n\n"
const syntheticNormal = "---\nname: original-display\ndescription: Inspect a synthetic stationery list.\nlicense: MIT\nmcps: [must-not-connect]\nmcp: must-not-connect-either\nallowed-tools: [Bash]\nhooks: [must-not-run]\n---\n" + syntheticBody
const syntheticLegacy = "# Legacy stationery list\n\nDescribe fictional pencils in prose.\nCopyright: synthetic fixture authors.\n"

func importerFixture(t *testing.T) (*Catalog, string, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	writeImporterFile(t, filepath.Join(source, "LICENSE"), []byte(syntheticLicense))
	writeImporterFile(t, filepath.Join(source, "Skills", "inventory", "normal", "SKILL.md"), []byte(syntheticNormal))
	writeImporterFile(t, filepath.Join(source, "Skills", "inventory", "legacy", "SKILL.md"), []byte(syntheticLegacy))
	c := &Catalog{
		SchemaVersion: SchemaVersion, Provider: "fixture", Namespace: "fixture",
		Source:       Source{Repository: "https://example.invalid/fixture", Revision: strings.Repeat("a", 40), License: License{Path: "LICENSE", SHA256: hashBytes([]byte(syntheticLicense)), SPDX: "MIT"}},
		Dependencies: []Dependency{{ID: "tool-stationery", Aliases: []string{"stationery"}}},
		Skills: []Entry{
			{ID: "normal", Category: "inventory", SourcePath: "Skills/inventory/normal/SKILL.md", SourceSHA256: hashBytes([]byte(syntheticNormal)), SourceBytes: int64(len(syntheticNormal)), Description: "Synthetic metadata description.", Format: "frontmatter", Provenance: "verified", ImportPolicy: "allowed", Dependencies: []string{"tool-stationery"}},
			{ID: "legacy", Category: "inventory", SourcePath: "Skills/inventory/legacy/SKILL.md", SourceSHA256: hashBytes([]byte(syntheticLegacy)), SourceBytes: int64(len(syntheticLegacy)), Description: "Describe fictional stationery.", Format: "legacy", Provenance: "verified", ImportPolicy: "allowed", Dependencies: []string{}},
		},
	}
	return c, source, filepath.Join(root, "imported")
}

func writeImporterFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readImporterFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cloneImporterCatalog(t *testing.T, c *Catalog) *Catalog {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out Catalog
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func assertImportAbsent(t *testing.T, destination string) {
	t.Helper()
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed import published destination: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "source" {
			t.Fatalf("failed import left temporary state %q", e.Name())
		}
	}
}

func TestProviderImportNormaContract(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic no-replace import currently supports Linux")
	}
	c, source, destination := importerFixture(t)
	if err := Import(context.Background(), c, source, destination, []string{"normal", "legacy"}); err != nil {
		t.Fatal(err)
	}
	reg, err := skill.LoadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 2 {
		t.Fatalf("real Norma loader found %d skills", len(reg.List()))
	}
	for i, original := range []string{syntheticNormal, syntheticLegacy} {
		e := c.Skills[i]
		name := SkillName(c, e)
		s, ok := reg.Get(name)
		if !ok {
			t.Fatalf("Norma missing namespaced %s", name)
		}
		if filepath.Base(s.Dir) != name || s.Name != name {
			t.Fatalf("visibility/metering key differs from name: %+v", s)
		}
		body := syntheticBody
		if i == 1 {
			body = syntheticLegacy
		}
		if s.Instructions != strings.TrimSpace(body) {
			t.Fatalf("loader body changed for %s: %q", name, s.Instructions)
		}
		if s.Description == "" || s.License != "MIT" || len(s.MCPs) != 0 {
			t.Fatalf("unsafe or incomplete parsed metadata: %+v", s)
		}
		generated := readImporterFile(t, filepath.Join(destination, name, "SKILL.md"))
		if !bytes.HasSuffix(generated, []byte(body)) {
			t.Fatalf("body bytes changed for %s", name)
		}
		if got := readImporterFile(t, filepath.Join(destination, name, "references", "source.md")); string(got) != original {
			t.Fatal("original source bytes were not retained")
		}
		if got := readImporterFile(t, filepath.Join(destination, name, "references", "LICENSE")); string(got) != syntheticLicense {
			t.Fatal("license bytes were not retained")
		}
	}
	var receipt Receipt
	if err := json.Unmarshal(readImporterFile(t, filepath.Join(destination, ReceiptFilename)), &receipt); err != nil {
		t.Fatal(err)
	}
	wantDigest, err := CatalogDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SchemaVersion != SchemaVersion || receipt.Provider != c.Provider || receipt.Namespace != c.Namespace || receipt.Revision != c.Source.Revision || receipt.CatalogSHA256 != wantDigest || len(receipt.Skills) != 2 {
		t.Fatalf("bad import receipt: %+v", receipt)
	}
	for _, r := range receipt.Skills {
		if hashBytes(readImporterFile(t, filepath.Join(destination, r.Name, "SKILL.md"))) != r.SkillSHA256 || hashBytes(readImporterFile(t, filepath.Join(destination, r.Name, "references", "source.md"))) != r.SourceSHA256 || r.LicenseSHA256 != c.Source.License.SHA256 {
			t.Fatalf("receipt does not identify imported bytes: %+v", r)
		}
	}
	if err := filepath.WalkDir(destination, func(name string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected symlink %s", name)
		}
		if !e.IsDir() {
			info, err := e.Info()
			if err != nil {
				return err
			}
			if info.Mode().Perm()&0o111 != 0 {
				return fmt.Errorf("import made file executable: %s", name)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProviderImportIsSelective(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic no-replace import currently supports Linux")
	}
	c, source, destination := importerFixture(t)
	// The unselected source need not exist and is never read.
	if err := os.Remove(filepath.Join(source, filepath.FromSlash(c.Skills[1].SourcePath))); err != nil {
		t.Fatal(err)
	}
	if err := Import(context.Background(), c, source, destination, []string{"normal"}); err != nil {
		t.Fatal(err)
	}
	reg, err := skill.LoadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 1 {
		t.Fatalf("imported unselected skills: %+v", reg.List())
	}
	if _, err := os.Stat(filepath.Join(destination, "fixture-legacy")); !os.IsNotExist(err) {
		t.Fatalf("unselected skill directory: %v", err)
	}
}

func TestProviderImportPreservesSourceDetails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic no-replace import currently supports Linux")
	}
	for _, tc := range []struct {
		name, source, body, license string
		legacy                      bool
	}{
		{name: "individual license", source: strings.Replace(syntheticNormal, "license: MIT", "license: Apache-2.0", 1), body: syntheticBody, license: "Apache-2.0"},
		{name: "crlf body", source: strings.ReplaceAll(syntheticNormal, "\n", "\r\n"), body: strings.ReplaceAll(syntheticBody, "\n", "\r\n"), license: "MIT"},
		{name: "legacy without final newline", source: strings.TrimSuffix(syntheticLegacy, "\n"), body: strings.TrimSuffix(syntheticLegacy, "\n"), license: "MIT", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, source, destination := importerFixture(t)
			idx := 0
			if tc.legacy {
				idx = 1
			}
			e := &c.Skills[idx]
			e.SourceSHA256 = hashBytes([]byte(tc.source))
			e.SourceBytes = int64(len(tc.source))
			writeImporterFile(t, filepath.Join(source, filepath.FromSlash(e.SourcePath)), []byte(tc.source))
			if err := Import(context.Background(), c, source, destination, []string{e.ID}); err != nil {
				t.Fatal(err)
			}
			name := SkillName(c, *e)
			generated := readImporterFile(t, filepath.Join(destination, name, "SKILL.md"))
			if !bytes.HasSuffix(generated, []byte(tc.body)) {
				t.Fatal("exact source body bytes changed")
			}
			if string(readImporterFile(t, filepath.Join(destination, name, "references", "source.md"))) != tc.source {
				t.Fatal("complete original source changed")
			}
			if string(readImporterFile(t, filepath.Join(destination, name, "references", "LICENSE"))) != syntheticLicense {
				t.Fatal("root license changed")
			}
			reg, err := skill.LoadDir(destination)
			if err != nil {
				t.Fatal(err)
			}
			loaded, ok := reg.Get(name)
			if !ok || loaded.License != tc.license {
				t.Fatalf("individual source license changed: %+v", loaded)
			}
		})
	}
}

func TestProviderImportBoundsCombinedOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic no-replace import currently supports Linux")
	}
	c, source, destination := importerFixture(t)
	body := bytes.Repeat([]byte("a"), MaxSourceBytes-2048)
	c.Skills = nil
	var ids []string
	for i := range 17 {
		id := fmt.Sprintf("large-%d", i)
		e := Entry{ID: id, Category: "inventory", SourcePath: fmt.Sprintf("Skills/%s/SKILL.md", id), SourceSHA256: hashBytes(body), SourceBytes: int64(len(body)), Description: "A large synthetic stationery list.", Format: "legacy", Provenance: "verified", ImportPolicy: "allowed"}
		c.Skills = append(c.Skills, e)
		ids = append(ids, id)
		writeImporterFile(t, filepath.Join(source, filepath.FromSlash(e.SourcePath)), body)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("input metadata should fit source limits: %v", err)
	}
	if err := Import(context.Background(), c, source, destination, ids); err == nil {
		t.Fatal("accepted combined original, generated, and license output beyond total byte limit")
	}
	assertImportAbsent(t, destination)
}

func TestProviderCatalogValidation(t *testing.T) {
	original, _, _ := importerFixture(t)
	tests := map[string]func(*Catalog){
		"unknown version":                func(c *Catalog) { c.SchemaVersion++ },
		"unpinned revision":              func(c *Catalog) { c.Source.Revision = "main" },
		"invalid license hash":           func(c *Catalog) { c.Source.License.SHA256 = "unknown" },
		"invalid source hash":            func(c *Catalog) { c.Skills[0].SourceSHA256 = strings.Repeat("z", 64) },
		"empty description":              func(c *Catalog) { c.Skills[0].Description = " \n" },
		"non utf8 description":           func(c *Catalog) { c.Skills[0].Description = string([]byte{0xff}) },
		"duplicate name":                 func(c *Catalog) { c.Skills[1].ID = c.Skills[0].ID },
		"duplicate source":               func(c *Catalog) { c.Skills[1].SourcePath = c.Skills[0].SourcePath },
		"long output name":               func(c *Catalog) { c.Namespace = strings.Repeat("a", 64) },
		"namespace collision":            func(c *Catalog) { c.Namespace = "fixture--invalid" },
		"unknown format":                 func(c *Catalog) { c.Skills[0].Format = "future" },
		"unknown provenance":             func(c *Catalog) { c.Skills[0].Provenance = "assumed" },
		"unknown import policy":          func(c *Catalog) { c.Skills[0].ImportPolicy = "install" },
		"unverified allowed":             func(c *Catalog) { c.Skills[0].Provenance = "provenance-unverified" },
		"unknown dependency":             func(c *Catalog) { c.Skills[0].Dependencies = []string{"missing-tool"} },
		"duplicate dependency reference": func(c *Catalog) { c.Skills[0].Dependencies = []string{"tool-stationery", "tool-stationery"} },
		"duplicate dependency id":        func(c *Catalog) { c.Dependencies = append(c.Dependencies, c.Dependencies[0]) },
		"alias collision": func(c *Catalog) {
			c.Dependencies = append(c.Dependencies, Dependency{ID: "tool-other", Aliases: []string{"STATIONERY"}})
		},
		"zero source size":  func(c *Catalog) { c.Skills[0].SourceBytes = 0 },
		"source size limit": func(c *Catalog) { c.Skills[0].SourceBytes = MaxSourceBytes + 1 },
		"empty catalog":     func(c *Catalog) { c.Skills = nil },
		"too many skills":   func(c *Catalog) { c.Skills = make([]Entry, MaxSkills+1) },
		"total source limit": func(c *Catalog) {
			c.Skills = nil
			for i := range 33 {
				e := original.Skills[0]
				e.ID = fmt.Sprintf("entry-%d", i)
				e.SourcePath = fmt.Sprintf("Skills/entry-%d/SKILL.md", i)
				e.SourceBytes = MaxSourceBytes
				c.Skills = append(c.Skills, e)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := cloneImporterCatalog(t, original)
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted invalid catalog")
			}
		})
	}
	for _, name := range []string{"../SKILL.md", "/SKILL.md", "a/../../SKILL.md", "a\\SKILL.md", "C:/SKILL.md", "a//SKILL.md", "a/./SKILL.md", ".", strings.Repeat("a", 241)} {
		t.Run("path "+name, func(t *testing.T) {
			c := cloneImporterCatalog(t, original)
			c.Skills[0].SourcePath = name
			if err := c.Validate(); err == nil {
				t.Fatalf("accepted unsafe source path %q", name)
			}
		})
	}
}

func TestProviderParseCatalogStrict(t *testing.T) {
	c, _, _ := importerFixture(t)
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCatalog(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"unknown field":        bytes.Replace(b, []byte(`"provider":`), []byte(`"unexpected":1,"provider":`), 1),
		"duplicate key":        bytes.Replace(b, []byte(`"provider":`), []byte(`"provider":"shadow","provider":`), 1),
		"duplicate nested key": bytes.Replace(b, []byte(`"repository":`), []byte(`"revision":"shadow","repository":`), 1),
		"trailing json":        append(append([]byte(nil), b...), []byte(` {}`)...),
		"non utf8":             {0xff},
		"size limit":           bytes.Repeat([]byte(" "), MaxCatalogBytes+1),
		"null":                 []byte("null"),
	}
	for name, bad := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCatalog(bytes.NewReader(bad)); err == nil {
				t.Fatal("accepted invalid catalog JSON")
			}
		})
	}
	canonicalDigest, err := CatalogDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCatalog(&pretty)
	if err != nil {
		t.Fatal(err)
	}
	prettyDigest, err := CatalogDigest(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalDigest != prettyDigest {
		t.Fatal("canonical digest depends on manifest whitespace")
	}
}

func TestProviderImportRefusesInvalidSelectionAndProvenance(t *testing.T) {
	for _, ids := range [][]string{nil, {}, {"missing"}, {"normal", "normal"}} {
		t.Run(fmt.Sprint(ids), func(t *testing.T) {
			c, source, destination := importerFixture(t)
			if err := Import(context.Background(), c, source, destination, ids); err == nil {
				t.Fatal("accepted invalid selection")
			}
			assertImportAbsent(t, destination)
		})
	}
	t.Run("unverified metadata only", func(t *testing.T) {
		c, source, destination := importerFixture(t)
		c.Skills[0].Provenance = "provenance-unverified"
		c.Skills[0].ImportPolicy = "metadata-only"
		if err := Import(context.Background(), c, source, destination, []string{"normal"}); err == nil {
			t.Fatal("unverified source imported")
		}
		assertImportAbsent(t, destination)
	})
}

func TestProviderImportAtomicFailureAndCancellation(t *testing.T) {
	for _, mode := range []string{"hash mismatch", "size mismatch", "missing source", "license mismatch", "oversized actual source", "oversized license", "non utf8 license", "non utf8", "empty source description", "malformed yaml", "duplicate yaml", "missing frontmatter", "unclosed frontmatter", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c, source, destination := importerFixture(t)
			ctx := context.Background()
			switch mode {
			case "hash mismatch":
				c.Skills[1].SourceSHA256 = strings.Repeat("0", 64)
			case "size mismatch":
				c.Skills[1].SourceBytes++
			case "missing source":
				if err := os.Remove(filepath.Join(source, filepath.FromSlash(c.Skills[1].SourcePath))); err != nil {
					t.Fatal(err)
				}
			case "license mismatch":
				c.Source.License.SHA256 = strings.Repeat("0", 64)
			case "oversized actual source":
				writeImporterFile(t, filepath.Join(source, filepath.FromSlash(c.Skills[1].SourcePath)), bytes.Repeat([]byte("a"), MaxSourceBytes+1))
			case "oversized license":
				license := bytes.Repeat([]byte("a"), 65537)
				c.Source.License.SHA256 = hashBytes(license)
				writeImporterFile(t, filepath.Join(source, "LICENSE"), license)
			case "non utf8 license":
				license := []byte{0xff}
				c.Source.License.SHA256 = hashBytes(license)
				writeImporterFile(t, filepath.Join(source, "LICENSE"), license)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			default:
				md := []byte{0xff}
				switch mode {
				case "empty source description":
					md = []byte("---\nname: simple\ndescription: '  '\n---\nbenign\n")
				case "malformed yaml":
					md = []byte("---\ndescription: [\n---\nbenign\n")
				case "duplicate yaml":
					md = []byte("---\ndescription: first\ndescription: second\n---\nbenign\n")
				case "missing frontmatter":
					md = []byte("plain benign prose\n")
				case "unclosed frontmatter":
					md = []byte("---\ndescription: benign\n")
				}
				c.Skills[1].Format = "frontmatter"
				c.Skills[1].SourceSHA256 = hashBytes(md)
				c.Skills[1].SourceBytes = int64(len(md))
				writeImporterFile(t, filepath.Join(source, filepath.FromSlash(c.Skills[1].SourcePath)), md)
			}
			if err := Import(ctx, c, source, destination, []string{"normal", "legacy"}); err == nil {
				t.Fatal("accepted bad import")
			}
			assertImportAbsent(t, destination)
		})
	}
}

type cancelWhenStaged struct {
	context.Context
	cancel   context.CancelFunc
	parent   string
	observed bool
}

// Observe the public filesystem boundary instead of relying on call counts or
// a timing race. This cancels after a staging root exists and before publication.
func (c *cancelWhenStaged) Err() error {
	entries, _ := os.ReadDir(c.parent)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".provider-stage-") {
			c.observed = true
			c.cancel()
		}
	}
	return c.Context.Err()
}

func TestProviderImportCancellationRemovesStaging(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic no-replace import currently supports Linux")
	}
	c, source, destination := importerFixture(t)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelWhenStaged{Context: base, cancel: cancel, parent: filepath.Dir(destination)}
	if err := Import(ctx, c, source, destination, []string{"normal", "legacy"}); err != context.Canceled {
		t.Fatalf("staging cancellation returned %v", err)
	}
	if !ctx.observed {
		t.Fatal("test did not reach staging boundary")
	}
	assertImportAbsent(t, destination)
}

func TestProviderImportRejectsLinksAndPreservesDestinations(t *testing.T) {
	for _, mode := range []string{"source file symlink", "source directory symlink", "source root symlink", "destination parent symlink", "destination symlink", "existing empty destination", "existing user file"} {
		t.Run(mode, func(t *testing.T) {
			c, source, destination := importerFixture(t)
			originalDestination := destination
			marker := []byte("user content must survive\n")
			switch mode {
			case "source file symlink":
				file := filepath.Join(source, filepath.FromSlash(c.Skills[0].SourcePath))
				saved := file + ".saved"
				if err := os.Rename(file, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(saved, file); err != nil {
					t.Fatal(err)
				}
			case "source directory symlink":
				dir := filepath.Join(source, "Skills", "inventory")
				saved := dir + ".saved"
				if err := os.Rename(dir, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(saved, dir); err != nil {
					t.Fatal(err)
				}
			case "source root symlink":
				link := source + "-link"
				if err := os.Symlink(source, link); err != nil {
					t.Fatal(err)
				}
				source = link
			case "destination parent symlink":
				parent := filepath.Join(filepath.Dir(destination), "parent")
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				link := parent + "-link"
				if err := os.Symlink(parent, link); err != nil {
					t.Fatal(err)
				}
				destination = filepath.Join(link, "imported")
			case "destination symlink":
				if err := os.Symlink(source, destination); err != nil {
					t.Fatal(err)
				}
			case "existing empty destination":
				if err := os.Mkdir(destination, 0o700); err != nil {
					t.Fatal(err)
				}
			case "existing user file":
				writeImporterFile(t, filepath.Join(destination, "user.txt"), marker)
			}
			if err := Import(context.Background(), c, source, destination, []string{"normal"}); err == nil {
				t.Fatal("accepted link/existing destination")
			}
			if mode == "existing user file" && !bytes.Equal(readImporterFile(t, filepath.Join(destination, "user.txt")), marker) {
				t.Fatal("user content overwritten")
			}
			if mode == "existing empty destination" {
				entries, err := os.ReadDir(destination)
				if err != nil || len(entries) != 0 {
					t.Fatalf("existing empty destination changed: %v, %v", entries, err)
				}
			}
			if mode == "destination symlink" {
				info, err := os.Lstat(originalDestination)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("destination symlink overwritten")
				}
			}
		})
	}
}

func TestProviderImportConcurrentNoReplace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic no-replace import currently supports Linux")
	}
	c, source, destination := importerFixture(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- Import(context.Background(), c, source, destination, []string{"normal"})
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent import had %d successful publishers, want exactly one", wins)
	}
	reg, err := skill.LoadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 1 {
		t.Fatal("published library incomplete")
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("staging state leaked: %v", entries)
	}
}
