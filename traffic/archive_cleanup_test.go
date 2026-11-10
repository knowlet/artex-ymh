package traffic

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestArchiveRollbackCleansOnlyNewBlobs(t *testing.T) {
	for _, failure := range []string{"bad_reference", "later_source"} {
		t.Run(failure, func(t *testing.T) {
			tr, root := openTraffic(t)
			body := []byte("new body")
			hash := archiveReferenceHash(body)
			old := []byte("preexisting orphan")
			oldHash := archiveReferenceHash(old)
			oldPath := archiveReferenceLocalPath(root, oldHash, "current")
			writeArchiveReferenceFile(t, oldPath, old)
			snapshot := ArchiveSnapshot{Version: 1, Blobs: []string{hash, oldHash}}
			files := map[string][]byte{hash: body, oldHash: old}
			if failure == "bad_reference" {
				bad := archiveReferenceExchange("bad")
				bad.RespBlob = archiveReferenceHash([]byte("missing"))
				snapshot.Exchanges = []ArchiveExchange{bad}
			} else {
				snapshot.Blobs = append(snapshot.Blobs, archiveReferenceHash([]byte("missing source")))
			}
			arc := writeArchiveReferenceFixture(t, snapshot, files)
			if _, err := tr.ImportArchive(arc); err == nil {
				t.Fatal("expected failed import")
			}
			if _, err := os.Stat(archiveReferenceLocalPath(root, hash, "current")); !os.IsNotExist(err) {
				t.Fatalf("new blob retained: %v", err)
			}
			if got, err := os.ReadFile(oldPath); err != nil || string(got) != string(old) {
				t.Fatalf("existing orphan changed %q %v", got, err)
			}
		})
	}
}

func TestArchiveCleanupProtectsLiveAndUncertainBlobs(t *testing.T) {
	for _, kind := range []string{"live_ref", "legacy_ref", "changed_identity", "query_failure", "legacy_file_symlink", "legacy_directory_symlink", "legacy_fifo"} {
		t.Run(kind, func(t *testing.T) {
			tr, root := openTraffic(t)
			body := []byte("retained body")
			hash := archiveReferenceHash(body)
			path := archiveReferenceLocalPath(root, hash, "current")
			writeArchiveReferenceFile(t, path, body)
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "live_ref":
				if _, err := tr.DB().Exec("INSERT INTO blob_refs(hash,exchange_id) VALUES(?,?)", hash, "live"); err != nil {
					t.Fatal(err)
				}
			case "legacy_ref":
				dir := filepath.Join(root, "legacy")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				writeArchiveReferenceFile(t, filepath.Join(dir, "response.http"), []byte("HTTP 200\n\n@blob sha256:"+hash))
				if _, err := tr.DB().Exec("INSERT INTO exchanges(id,path) VALUES(?,?)", "legacy", "legacy"); err != nil {
					t.Fatal(err)
				}
			case "legacy_file_symlink", "legacy_directory_symlink":
				dir := filepath.Join(root, "legacy")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				linkPath := filepath.Join(dir, "response.http")
				target := filepath.Join(root, "missing-target")
				legacyPath := "legacy"
				if kind == "legacy_directory_symlink" {
					linkPath = filepath.Join(root, "legacy-link")
					legacyPath = "legacy-link"
					target = t.TempDir()
					writeArchiveReferenceFile(t, filepath.Join(target, "response.http"), []byte("HTTP 200\n\n@blob sha256:"+hash))
				}
				err := os.Symlink(target, linkPath)
				if runtime.GOOS == "windows" && (errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.Errno(1314)) || errors.Is(err, syscall.Errno(50))) {
					t.Skipf("symlink fixture unavailable: %v", err)
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tr.DB().Exec("INSERT INTO exchanges(id,path) VALUES(?,?)", "legacy", legacyPath); err != nil {
					t.Fatal(err)
				}
			case "legacy_fifo":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX FIFO fixture")
				}
				mkfifo, err := exec.LookPath("mkfifo")
				if err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(root, "legacy")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(mkfifo, filepath.Join(dir, "response.http")).CombinedOutput(); err != nil {
					t.Fatalf("FIFO fixture: %s %v", out, err)
				}
				if _, err := tr.DB().Exec("INSERT INTO exchanges(id,path) VALUES(?,?)", "legacy", "legacy"); err != nil {
					t.Fatal(err)
				}
			case "changed_identity":
				writeArchiveReferenceFile(t, path+".other", body)
				if err := os.Rename(path+".other", path); err != nil {
					t.Fatal(err)
				}
			case "query_failure":
				if err := tr.DB().Close(); err != nil {
					t.Fatal(err)
				}
			}
			tr.wmu.Lock()
			err = tr.cleanupArchiveBlobs(map[string]os.FileInfo{hash: info})
			tr.wmu.Unlock()
			if kind == "query_failure" || kind == "changed_identity" || kind == "legacy_file_symlink" || kind == "legacy_directory_symlink" || kind == "legacy_fifo" {
				if err == nil || !strings.Contains(err.Error(), "retained") {
					t.Fatalf("uncertainty not reported: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("protected blob removed: %v", err)
			}
		})
	}
}

func TestArchiveCommitFailureRetainsNewBlob(t *testing.T) {
	tr, root := openTraffic(t)
	tr.DB().SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA foreign_keys=ON",
		"CREATE TABLE archive_test_parent(id TEXT PRIMARY KEY)",
		"CREATE TABLE archive_test_child(id TEXT REFERENCES archive_test_parent(id) DEFERRABLE INITIALLY DEFERRED)",
		"CREATE TRIGGER archive_test_commit_failure AFTER INSERT ON exchanges BEGIN INSERT INTO archive_test_child(id) VALUES('missing-parent'); END",
	} {
		if _, err := tr.DB().Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	body := []byte("retained after uncertain commit")
	arc, hash := archiveBlobFixture(t, body)
	_, err := tr.ImportArchive(arc)
	if err == nil || !strings.Contains(err.Error(), "rollback unconfirmed") {
		t.Fatalf("expected uncertain transaction: %v", err)
	}
	if got, err := os.ReadFile(archiveReferenceLocalPath(root, hash, "current")); err != nil || string(got) != string(body) {
		t.Fatalf("uncertain blob lost: %q %v", got, err)
	}
}

func TestArchiveCleanupSkipsStoreOwnedSymlink(t *testing.T) {
	tr, root := openTraffic(t)
	tr.dir = root + string(os.PathSeparator) // Open preserves caller-supplied trailing separators.
	body := []byte("unreferenced new body")
	hash := archiveReferenceHash(body)
	path := archiveReferenceLocalPath(root, hash, "current")
	writeArchiveReferenceFile(t, path, body)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec("INSERT INTO exchanges(id,path) VALUES(?,?)", "legacy", "legacy"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "ca")
	if err := os.Rename(filepath.Join(root, "_ca"), target); err != nil {
		t.Fatal(err)
	}
	err = os.Symlink(target, filepath.Join(root, "_ca"))
	if runtime.GOOS == "windows" && (errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.Errno(1314)) || errors.Is(err, syscall.Errno(50))) {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	tr.wmu.Lock()
	err = tr.cleanupArchiveBlobs(map[string]os.FileInfo{hash: info})
	tr.wmu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reserved symlink blocked cleanup: %v", err)
	}
}

func TestArchiveCleanupTraversesReferenceNamedDirectories(t *testing.T) {
	for _, name := range []string{"request.http", "response.http"} {
		t.Run(name, func(t *testing.T) {
			tr, root := openTraffic(t)
			body := []byte("legacy nested body")
			hash := archiveReferenceHash(body)
			path := archiveReferenceLocalPath(root, hash, "current")
			writeArchiveReferenceFile(t, path, body)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			rel := filepath.Join("legacy", name, "nested")
			writeArchiveReferenceFile(t, filepath.Join(root, rel, "response.http"), []byte("HTTP 200\n\n@blob sha256:"+hash))
			if _, err := tr.DB().Exec("INSERT INTO exchanges(id,path) VALUES(?,?)", "legacy", rel); err != nil {
				t.Fatal(err)
			}
			tr.wmu.Lock()
			err = tr.cleanupArchiveBlobs(map[string]os.FileInfo{hash: info})
			tr.wmu.Unlock()
			if err != nil {
				t.Fatalf("valid legacy directory rejected: %v", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("legacy referenced body lost: %v", err)
			}
		})
	}
}

func TestLegacyReferencesSurviveRootSymlinkAndNestedUnderscore(t *testing.T) {
	for _, layout := range []string{"root_symlink", "nested_underscore"} {
		for _, collector := range []string{"gc", "rollback_cleanup"} {
			t.Run(layout+"/"+collector, func(t *testing.T) {
				root := t.TempDir()
				openPath := root
				if layout == "root_symlink" {
					link := filepath.Join(t.TempDir(), "store")
					err := os.Symlink(root, link)
					if runtime.GOOS == "windows" && (errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.Errno(1314)) || errors.Is(err, syscall.Errno(50))) {
						t.Skipf("symlink unavailable: %v", err)
					}
					if err != nil {
						t.Fatal(err)
					}
					openPath = link + string(os.PathSeparator)
				}
				tr, err := Open(openPath, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { tr.Close() })
				body := []byte("legacy referenced body")
				hash := archiveReferenceHash(body)
				path := archiveReferenceLocalPath(root, hash, "current")
				writeArchiveReferenceFile(t, path, body)
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				rel := filepath.Join("legacy", "call")
				if layout == "nested_underscore" {
					rel = filepath.Join("legacy", "_api", "call")
				}
				writeArchiveReferenceFile(t, filepath.Join(root, rel, "response.http"), []byte("HTTP 200\n\n@blob sha256:"+hash))
				if _, err := tr.DB().Exec("INSERT INTO exchanges(id,path) VALUES(?,?)", "legacy", rel); err != nil {
					t.Fatal(err)
				}
				tr.wmu.Lock()
				if collector == "gc" {
					err = tr.gcBlobs()
				} else {
					err = tr.cleanupArchiveBlobs(map[string]os.FileInfo{hash: info})
				}
				tr.wmu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != string(body) {
					t.Fatalf("live legacy body lost: %q %v", got, err)
				}
			})
		}
	}
}

func TestArchiveCleanupPreservesUncertainDeleteStages(t *testing.T) {
	for _, kind := range []string{"empty", "recoverable"} {
		t.Run(kind, func(t *testing.T) {
			tr, root := openTraffic(t)
			body := []byte("possibly staged reference")
			hash := archiveReferenceHash(body)
			path := archiveReferenceLocalPath(root, hash, "current")
			writeArchiveReferenceFile(t, path, body)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			stage := filepath.Join(root, "_delete_staging")
			if err := os.MkdirAll(stage, 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "recoverable" {
				writeArchiveReferenceFile(t, filepath.Join(stage, "pending", "response.http"), []byte("HTTP 200\n\n@blob sha256:"+hash))
			}
			tr.wmu.Lock()
			err = tr.cleanupArchiveBlobs(map[string]os.FileInfo{hash: info})
			tr.wmu.Unlock()
			if kind == "recoverable" {
				if err == nil || !strings.Contains(err.Error(), "recovery state unknown") {
					t.Fatalf("unknown stage not reported: %v", err)
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("possibly recoverable body lost: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("empty stage blocked cleanup: %v", err)
				}
			}
		})
	}
}
