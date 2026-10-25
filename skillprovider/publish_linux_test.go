//go:build linux

package skillprovider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Simulate a target created after the initial absence check. Ordinary rename
// would replace this empty user directory; publication must leave both intact.
func TestProviderPublishRefusesConcurrentEmptyDirectory(t *testing.T) {
	path := t.TempDir()
	parent, err := openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := parent.mkdir("staged"); err != nil {
		t.Fatal(err)
	}
	if err := parent.requireAbsent("published"); err != nil {
		t.Fatal(err)
	}
	if err := parent.mkdir("published"); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(path, "published"))
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.renameNoReplace("staged", "published"); err == nil {
		t.Fatal("replaced a concurrently created empty target")
	}
	after, err := os.Stat(filepath.Join(path, "published"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("empty user directory was replaced")
	}
	if _, err := os.Stat(filepath.Join(path, "staged")); err != nil {
		t.Fatalf("failed publication consumed staging: %v", err)
	}
}

// replaceOuterStageContext waits for the import receipt, then deterministically
// substitutes the visible staging name immediately before publication. It models
// a writer to the output parent; it does not alter the pinned inner library.
type replaceOuterStageContext struct {
	context.Context
	parent            string
	refusePublication bool
	outerName         string
	movedName         string
	err               error
}

func (c *replaceOuterStageContext) Err() error {
	if c.err != nil {
		return c.err
	}
	if c.outerName != "" {
		return c.Context.Err()
	}
	entries, err := os.ReadDir(c.parent)
	if err != nil {
		c.err = err
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".provider-stage-") {
			continue
		}
		outer := filepath.Join(c.parent, entry.Name())
		if _, err := os.Stat(filepath.Join(outer, "library", ReceiptFilename)); err != nil {
			continue
		}
		c.outerName = outer
		c.movedName = outer + "-moved"
		if err := os.Rename(outer, c.movedName); err != nil {
			c.err = err
			return err
		}
		if err := os.Mkdir(outer, 0700); err != nil {
			c.err = err
			return err
		}
		if err := os.WriteFile(filepath.Join(outer, "UNVERIFIED"), []byte("replacement user content\n"), 0600); err != nil {
			c.err = err
			return err
		}
		if c.refusePublication {
			target := filepath.Join(c.parent, "imported")
			if err := os.Mkdir(target, 0700); err != nil {
				c.err = err
				return err
			}
			if err := os.WriteFile(filepath.Join(target, "USER"), []byte("existing destination content\n"), 0600); err != nil {
				c.err = err
				return err
			}
		}
		return nil
	}
	return c.Context.Err()
}

func TestProviderPublicationUsesPinnedStageParent(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("destination-conflict-%v", refuse), func(t *testing.T) {
			catalog, source, destination := importerFixture(t)
			ctx := &replaceOuterStageContext{Context: context.Background(), parent: filepath.Dir(destination), refusePublication: refuse}
			err := Import(ctx, catalog, source, destination, []string{"normal"})
			if ctx.outerName == "" || ctx.err != nil {
				t.Fatalf("stage substitution hook did not complete: %v", ctx.err)
			}
			if (err != nil) != refuse {
				t.Fatalf("Import returned %v, refused=%v", err, refuse)
			}
			if got := readImporterFile(t, filepath.Join(ctx.outerName, "UNVERIFIED")); string(got) != "replacement user content\n" {
				t.Fatal("cleanup touched replacement user content")
			}
			entries, err := os.ReadDir(ctx.outerName)
			if err != nil || len(entries) != 1 {
				t.Fatalf("replacement directory changed: %v %v", entries, err)
			}
			if _, err := os.Lstat(filepath.Join(ctx.movedName, "library")); !os.IsNotExist(err) {
				t.Fatalf("prepared library remained after publish/cleanup: %v", err)
			}
			if refuse {
				if got := readImporterFile(t, filepath.Join(destination, "USER")); string(got) != "existing destination content\n" {
					t.Fatal("existing destination modified")
				}
				return
			}
			if _, err := os.Lstat(filepath.Join(destination, "UNVERIFIED")); !os.IsNotExist(err) {
				t.Fatal("replacement staging contents published")
			}
			name := SkillName(catalog, catalog.Skills[0])
			if got := readImporterFile(t, filepath.Join(destination, name, "references", "source.md")); !bytes.Equal(got, []byte(syntheticNormal)) {
				t.Fatal("published source does not match prepared bytes")
			}
			if got := readImporterFile(t, filepath.Join(destination, name, "SKILL.md")); !bytes.HasSuffix(got, []byte(syntheticBody)) {
				t.Fatal("published document does not contain prepared body")
			}
			if _, err := os.Stat(filepath.Join(destination, ReceiptFilename)); err != nil {
				t.Fatalf("verified import receipt missing: %v", err)
			}
		})
	}
}

// Reproduce substitution between mkdir and open without relying on a watcher.
// Import performs this same fd-based validation before creating inner library
// state or installing its cleanup, so permissive replacements stay untouched.
func TestProviderStagingRejectsPermissiveReplacement(t *testing.T) {
	path := t.TempDir()
	parent, err := openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := parent.mkdir("outer"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(path, "outer"), filepath.Join(path, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(path, "outer"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(path, "outer"), 0777); err != nil {
		t.Fatal(err)
	}
	marker := []byte("permissive replacement user data\n")
	writeImporterFile(t, filepath.Join(path, "outer", "USER"), marker)
	outer, err := parent.child("outer")
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	if err := outer.requirePrivate(); err == nil {
		t.Fatal("permissive replacement accepted as private staging")
	}
	if got := readImporterFile(t, filepath.Join(path, "outer", "USER")); !bytes.Equal(got, marker) {
		t.Fatal("replacement data changed")
	}
	entries, err := os.ReadDir(filepath.Join(path, "outer"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("unverified outer directory changed: %v %v", entries, err)
	}
	private, err := parent.child("moved")
	if err != nil {
		t.Fatal(err)
	}
	defer private.Close()
	if err := private.requirePrivate(); err != nil {
		t.Fatalf("owned 0700 staging rejected: %v", err)
	}
}
