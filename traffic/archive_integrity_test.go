package traffic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"testing/iotest"
)

func archiveBlobFixture(t *testing.T, body []byte) (dir, hash string) {
	t.Helper()
	dir = t.TempDir()
	sum := sha256.Sum256(body)
	hash = hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", hash+".bin"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := ArchiveSnapshot{
		Version: 1,
		Blobs:   []string{hash},
		Exchanges: []ArchiveExchange{{
			ID: "blob-integrity-exchange", Host: "archive.invalid", Method: "GET",
			URL: "https://archive.invalid/", URLTemplate: "/", Status: 200,
			RespHead: "HTTP/1.1 200 OK", RespLen: len(body), RespBlob: hash,
		}},
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "traffic.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, hash
}

func TestTrafficArchiveRejectsCorruptExistingBlob(t *testing.T) {
	body := []byte("complete archived response")
	for name, corrupt := range map[string][]byte{
		"empty":       {},
		"truncated":   body[:4],
		"same_length": bytes.Repeat([]byte("x"), len(body)),
	} {
		t.Run(name, func(t *testing.T) {
			archiveDir, hash := archiveBlobFixture(t, body)
			trafficDir := t.TempDir()
			tr, err := Open(trafficDir, "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Close()
			destination := filepath.Join(trafficDir, "_blobs", "sha256", hash[:2], hash+".bin")
			if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, corrupt, 0o600); err != nil {
				t.Fatal(err)
			}
			imported, err := tr.ImportArchive(archiveDir)
			if err == nil || imported != 0 {
				t.Fatalf("corrupt destination accepted: imported=%d err=%v", imported, err)
			}
			got, err := os.ReadFile(destination)
			if err != nil || !bytes.Equal(got, corrupt) {
				t.Fatalf("existing damaged blob changed: got=%q err=%v", got, err)
			}
			var count int
			if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed import committed exchanges: count=%d err=%v", count, err)
			}
		})
	}
}

func TestTrafficArchiveBlobRestoreAndVerifiedReuse(t *testing.T) {
	body := []byte("complete archived response")
	archiveDir, hash := archiveBlobFixture(t, body)
	trafficDir := t.TempDir()
	tr, err := Open(trafficDir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if count, err := tr.ImportArchive(archiveDir); err != nil || count != 1 {
		t.Fatalf("initial blob import: count=%d err=%v", count, err)
	}
	destination := filepath.Join(trafficDir, "_blobs", "sha256", hash[:2], hash+".bin")
	before, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyArchiveBlob(destination, hash, int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if count, err := tr.ImportArchive(archiveDir); err != nil || count != 0 {
		t.Fatalf("idempotent blob import: count=%d err=%v", count, err)
	}
	after, err := os.Stat(destination)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("valid existing blob replaced or modified: err=%v", err)
	}
	data, total, err := tr.BlobRange(hash, 0, int64(len(body)))
	if err != nil || total != int64(len(body)) || !bytes.Equal(data, body) {
		t.Fatalf("restored blob differs: data=%q total=%d err=%v", data, total, err)
	}
	assertArchiveBlobDirectory(t, filepath.Dir(destination), filepath.Base(destination))
}

func TestTrafficArchiveRejectsNonRegularExistingBlob(t *testing.T) {
	for _, kind := range []string{"directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			body := []byte("complete archived response")
			archiveDir, hash := archiveBlobFixture(t, body)
			trafficDir := t.TempDir()
			tr, err := Open(trafficDir, "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Close()
			destination := filepath.Join(trafficDir, "_blobs", "sha256", hash[:2], hash+".bin")
			if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
				t.Fatal(err)
			}
			if kind == "directory" {
				err = os.Mkdir(destination, 0o700)
			} else {
				err = os.Symlink(filepath.Join(archiveDir, "blobs", hash+".bin"), destination)
				// Windows may require Developer Mode or elevated privileges for
				// this fixture. Do not skip unrelated errors or the directory case.
				if runtime.GOOS == "windows" && (errors.Is(err, os.ErrPermission) ||
					errors.Is(err, syscall.Errno(1314)) || errors.Is(err, syscall.Errno(50))) {
					t.Skipf("Windows symlink fixture unavailable (privilege or filesystem support): %v", err)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if count, err := tr.ImportArchive(archiveDir); err == nil || count != 0 {
				t.Fatalf("non-regular destination accepted: count=%d err=%v", count, err)
			}
			var count int
			if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed import committed exchanges: count=%d err=%v", count, err)
			}
		})
	}
}

func TestTrafficArchiveRejectsCorruptSourceBlob(t *testing.T) {
	body := []byte("complete archived response")
	archiveDir, hash := archiveBlobFixture(t, body)
	if err := os.WriteFile(filepath.Join(archiveDir, "blobs", hash+".bin"), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	trafficDir := t.TempDir()
	tr, err := Open(trafficDir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if count, err := tr.ImportArchive(archiveDir); err == nil || count != 0 {
		t.Fatalf("corrupt source accepted: count=%d err=%v", count, err)
	}
	assertArchiveBlobDirectory(t, filepath.Join(trafficDir, "_blobs"))
}

func TestWriteArchiveBlobFailureLeavesNoFinalFile(t *testing.T) {
	body := []byte("complete archived response")
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	failure := errors.New("simulated read interruption")
	for _, test := range []struct {
		name   string
		reader io.Reader
		want   error
	}{
		{"interrupted", io.MultiReader(bytes.NewReader(body[:4]), iotest.ErrReader(failure)), failure},
		{"short", bytes.NewReader(body[:4]), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, hash+".bin")
			err := writeArchiveBlob(destination, test.reader, hash, int64(len(body)))
			if err == nil || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("copy failure not propagated: %v", err)
			}
			assertArchiveBlobDirectory(t, dir)
			if err := writeArchiveBlob(destination, bytes.NewReader(body), hash, int64(len(body))); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
			if err := verifyArchiveBlob(destination, hash, int64(len(body))); err != nil {
				t.Fatal(err)
			}
			assertArchiveBlobDirectory(t, dir, filepath.Base(destination))
		})
	}
}

func TestWriteArchiveBlobRechecksDestinationBeforePublish(t *testing.T) {
	body := []byte("complete archived response")
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	for _, valid := range []bool{false, true} {
		name := "corrupt"
		if valid {
			name = "valid"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, hash+".bin")
			existing := []byte("partial")
			if valid {
				existing = body
			}
			if err := os.WriteFile(destination, existing, 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(destination)
			if err != nil {
				t.Fatal(err)
			}
			err = writeArchiveBlob(destination, bytes.NewReader(body), hash, int64(len(body)))
			if (err == nil) != valid {
				t.Fatalf("destination valid=%v, publication err=%v", valid, err)
			}
			after, err := os.Stat(destination)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatalf("existing destination replaced: %v", err)
			}
			got, err := os.ReadFile(destination)
			if err != nil || !bytes.Equal(got, existing) {
				t.Fatalf("existing destination changed: got=%q err=%v", got, err)
			}
			assertArchiveBlobDirectory(t, dir, filepath.Base(destination))
		})
	}
}

func assertArchiveBlobDirectory(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(names) {
		t.Fatalf("unexpected blob/staging entries: %v", entries)
	}
	for i, name := range names {
		if entries[i].Name() != name {
			t.Fatalf("entry=%q, want %q", entries[i].Name(), name)
		}
	}
}
