//go:build linux

package skillprovider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func recoveryFixture(t *testing.T) (string, *safeDir) {
	t.Helper()
	root := t.TempDir()
	name := ".provider-stage-" + strings.Repeat("a", 32)
	stage := filepath.Join(root, name)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := openDirectory(stage)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	if err := dir.lockStage(); err != nil {
		t.Fatal(err)
	}
	files := []stagedFile{
		{"library/fixture-notes/SKILL.md", 5, hashBytes([]byte("notes"))},
		{"library/" + ReceiptFilename, 2, hashBytes([]byte("{}"))},
	}
	if err := dir.writeStageRecord(name, files); err != nil {
		t.Fatal(err)
	}
	return stage, dir
}

func TestProviderRecoveryInactivePartialAndCommittedStages(t *testing.T) {
	for _, mode := range []string{"empty", "empty-library", "partial", "full"} {
		t.Run(mode, func(t *testing.T) {
			stage, dir := recoveryFixture(t)
			if mode == "empty-library" {
				if err := os.Mkdir(filepath.Join(stage, "library"), 0700); err != nil {
					t.Fatal(err)
				}
			} else if mode != "empty" {
				writeImporterFile(t, filepath.Join(stage, "library/fixture-notes/SKILL.md"), []byte("notes"))
			}
			if mode == "full" {
				writeImporterFile(t, filepath.Join(stage, "library", ReceiptFilename), []byte("{}"))
			}
			// Unlock models the advisory lock released by a dead importer.
			if err := unix.Flock(dir.fd, unix.LOCK_UN); err != nil {
				t.Fatal(err)
			}
			if err := RecoverStage(context.Background(), stage); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(stage); !os.IsNotExist(err) {
				t.Fatalf("stage remained: %v", err)
			}
			if err := RecoverStage(context.Background(), stage); err == nil {
				t.Fatal("missing stage reported recovered twice")
			}
		})
	}
}

func TestProviderRecoveryRefusesActiveAndChangedContent(t *testing.T) {
	for _, mode := range []string{"active", "extra", "edited", "partial-file", "symlink", "hardlink", "copied-marker", "missing-marker", "invalid-marker", "public-marker", "public-file", "public-dir", "public-root"} {
		t.Run(mode, func(t *testing.T) {
			stage, dir := recoveryFixture(t)
			skill := filepath.Join(stage, "library/fixture-notes/SKILL.md")
			writeImporterFile(t, skill, []byte("notes"))
			if mode != "active" {
				if err := unix.Flock(dir.fd, unix.LOCK_UN); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "extra":
				writeImporterFile(t, filepath.Join(stage, "library", "USER"), []byte("retain"))
			case "edited":
				writeImporterFile(t, skill, []byte("edits"))
			case "partial-file":
				writeImporterFile(t, skill, []byte("no"))
			case "symlink":
				os.Remove(skill)
				if err := os.Symlink("/dev/null", skill); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(skill, filepath.Join(filepath.Dir(stage), "retain")); err != nil {
					t.Fatal(err)
				}
			case "copied-marker":
				other := filepath.Join(filepath.Dir(stage), ".provider-stage-"+strings.Repeat("b", 32))
				if err := os.Mkdir(other, 0700); err != nil {
					t.Fatal(err)
				}
				writeImporterFile(t, filepath.Join(other, stageRecordFilename), readImporterFile(t, filepath.Join(stage, stageRecordFilename)))
				stage = other
			case "missing-marker":
				os.Remove(filepath.Join(stage, stageRecordFilename))
			case "invalid-marker":
				writeImporterFile(t, filepath.Join(stage, stageRecordFilename), []byte("{}"))
			case "public-marker":
				if err := os.Chmod(filepath.Join(stage, stageRecordFilename), 0644); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(skill, 0644); err != nil {
					t.Fatal(err)
				}
			case "public-dir":
				if err := os.Chmod(filepath.Dir(skill), 0755); err != nil {
					t.Fatal(err)
				}
			case "public-root":
				if err := os.Chmod(stage, 0755); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshotRecoveryTree(t, stage)
			if err := RecoverStage(context.Background(), stage); err == nil {
				t.Fatal("unsafe recovery was accepted")
			}
			if after := snapshotRecoveryTree(t, stage); before != after {
				t.Fatalf("rejected recovery changed contents: before=%s after=%s", before, after)
			}
		})
	}
}

func TestProviderRecoveryCancellationAndStageSymlinkPreserveData(t *testing.T) {
	stage, dir := recoveryFixture(t)
	if err := unix.Flock(dir.fd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	before := snapshotRecoveryTree(t, stage)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RecoverStage(ctx, stage); err != context.Canceled {
		t.Fatalf("cancelled recovery: %v", err)
	}
	link := filepath.Join(t.TempDir(), filepath.Base(stage))
	if err := os.Symlink(stage, link); err != nil {
		t.Fatal(err)
	}
	if err := RecoverStage(context.Background(), link); err == nil {
		t.Fatal("followed stage symlink")
	}
	if after := snapshotRecoveryTree(t, stage); before != after {
		t.Fatal("rejected recovery changed stage data")
	}
}

func snapshotRecoveryTree(t *testing.T, root string) string {
	t.Helper()
	var result strings.Builder
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fmt.Fprintf(&result, "%s:%s\n", strings.TrimPrefix(name, root), entry.Type())
		if entry.Type().IsRegular() {
			result.Write(readImporterFile(t, name))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.String()
}

type killedStageContext struct {
	context.Context
	parent string
}

func (c killedStageContext) Err() error {
	entries, _ := os.ReadDir(c.parent)
	for _, entry := range entries {
		if !validStageName(entry.Name()) {
			continue
		}
		if _, err := os.Stat(filepath.Join(c.parent, entry.Name(), "library", ReceiptFilename)); err == nil {
			fmt.Println("staged")
			<-time.After(time.Hour)
		}
	}
	return nil
}

func TestProviderRecoveryKilledImporterHelper(t *testing.T) {
	if os.Getenv("ARTEX_RECOVERY_HELPER") != "1" {
		return
	}
	catalog, err := LoadCatalogFile(os.Getenv("ARTEX_RECOVERY_CATALOG"))
	if err != nil {
		t.Fatal(err)
	}
	destination := os.Getenv("ARTEX_RECOVERY_DEST")
	ctx := killedStageContext{context.Background(), filepath.Dir(destination)}
	if err := Import(ctx, catalog, os.Getenv("ARTEX_RECOVERY_SOURCE"), destination, []string{catalog.Skills[0].ID}); err != nil {
		t.Fatal(err)
	}
	t.Fatal("helper import did not block")
}

func TestProviderRecoveryAfterActualSIGKILL(t *testing.T) {
	catalog, source, destination := importerFixture(t)
	// Exercise the full generated-name boundary while recovering real output.
	catalog.Namespace = strings.Repeat("n", 31)
	catalog.Skills[0].ID = strings.Repeat("i", 32)
	data, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(filepath.Dir(destination), "catalog.json")
	writeImporterFile(t, catalogPath, data)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProviderRecoveryKilledImporterHelper$", "-test.count=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "ARTEX_RECOVERY_HELPER=1", "ARTEX_RECOVERY_CATALOG="+catalogPath, "ARTEX_RECOVERY_SOURCE="+source, "ARTEX_RECOVERY_DEST="+destination)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	scanner := bufio.NewScanner(pipe)
	var logs strings.Builder
	ready := false
	for scanner.Scan() {
		if scanner.Text() == "staged" {
			ready = true
			break
		}
		logs.WriteString(scanner.Text() + "\n")
	}
	if !ready {
		_ = cmd.Process.Kill()
		waitErr := cmd.Wait()
		t.Fatalf("helper did not finish staging: wait=%v scan=%v stdout=%s stderr=%s", waitErr, scanner.Err(), &logs, &stderr)
	}
	stages, err := filepath.Glob(filepath.Join(filepath.Dir(destination), ".provider-stage-*"))
	if err != nil || len(stages) != 1 {
		t.Fatalf("stage count: %v %v", stages, err)
	}
	if err := RecoverStage(context.Background(), stages[0]); err == nil {
		t.Fatal("recovered live process staging")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("helper was not killed")
	}
	if err := RecoverStage(context.Background(), stages[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("recovery created or changed destination")
	}
}
