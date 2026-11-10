package traffic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Pause after a real full hash, before commit, to model a slow filesystem read
// without timing-sensitive large allocations or process-global test hooks.
func pausedArchiveVerifier(entered, release chan struct{}) func(string, string, int64) (os.FileInfo, error) {
	return func(path, hash string, length int64) (os.FileInfo, error) {
		info, err := inspectArchiveBlob(path, hash, length)
		close(entered)
		<-release
		return info, err
	}
}

func existingArchiveFixture(t *testing.T) (*Traffic, string, string, []byte) {
	t.Helper()
	body := bytes.Repeat([]byte("archive body"), 64)
	arc, hash := archiveBlobFixture(t, body)
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	dest := filepath.Join(tr.dir, "_blobs", "sha256", hash[:2], hash+".bin")
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, body, 0600); err != nil {
		t.Fatal(err)
	}
	return tr, arc, dest, body
}

func TestArchiveVerificationDoesNotBlockRecording(t *testing.T) {
	tr, arc, _, _ := existingArchiveFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := tr.importArchive(arc, pausedArchiveVerifier(entered, release)); done <- err }()
	<-entered
	captured := make(chan struct{})
	go func() {
		tr.record(newFlow("capture.invalid", "GET", "/", nil, []byte("live capture")))
		close(captured)
	}()
	select {
	case <-captured:
	case <-time.After(5 * time.Second):
		close(release)
		<-done
		t.Fatal("slow destination verification blocked recording")
	}
	var count int
	if err := tr.DB().QueryRow("SELECT count(*) FROM exchanges WHERE host='capture.invalid'").Scan(&count); err != nil || count != 1 {
		close(release)
		<-done
		t.Fatalf("capture not persisted: %d %v", count, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestArchiveVerificationRejectsConcurrentBlobChanges(t *testing.T) {
	for _, change := range []string{"gc", "replace-valid", "replace-corrupt", "modify"} {
		t.Run(change, func(t *testing.T) {
			tr, arc, dest, body := existingArchiveFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			type result struct {
				n   int64
				err error
			}
			done := make(chan result, 1)
			go func() {
				n, err := tr.importArchive(arc, pausedArchiveVerifier(entered, release))
				done <- result{n, err}
			}()
			<-entered
			tr.wmu.Lock()
			var err error
			switch change {
			case "gc":
				err = tr.gcBlobs()
			case "replace-valid", "replace-corrupt":
				replacement := body
				if change == "replace-corrupt" {
					replacement = bytes.Repeat([]byte("x"), len(body))
				}
				// Rename keeps the old inode alive until replacement, avoiding inode reuse
				// in the test. Production GC may delete/recreate; metadata is also checked.
				err = os.WriteFile(dest+".replacement", replacement, 0600)
				if err == nil {
					err = os.Rename(dest+".replacement", dest)
				}
			case "modify":
				err = os.WriteFile(dest, []byte("damaged"), 0600)
			}
			tr.wmu.Unlock()
			close(release)
			r := <-done
			if err != nil {
				t.Fatal(err)
			}
			if r.err == nil || r.n != 0 || !strings.Contains(r.err.Error(), "verification") {
				t.Fatalf("changed destination accepted: n=%d err=%v", r.n, r.err)
			}
			var count int
			if err := tr.DB().QueryRow("SELECT count(*) FROM exchanges").Scan(&count); err != nil || count != 0 {
				t.Fatalf("race committed rows: %d %v", count, err)
			}
			if change == "gc" {
				if _, err := os.Lstat(dest); !os.IsNotExist(err) {
					t.Fatalf("GC removal undone: %v", err)
				}
			}
		})
	}
}

func TestArchiveConcurrentImportAndDuplicateHashes(t *testing.T) {
	tr, arc, _, _ := existingArchiveFixture(t)
	// A repeated manifest hash remains compatible, both for preexisting and new
	// bodies. Concurrent imports retain current-row-wins after full verification.
	raw, err := os.ReadFile(filepath.Join(arc, "traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot ArchiveSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Blobs = append(snapshot.Blobs, snapshot.Blobs[0])
	raw, err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(arc, "traffic.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := tr.importArchive(arc, pausedArchiveVerifier(entered, release)); done <- err }()
	<-entered
	n, err := tr.ImportArchive(arc)
	close(release)
	firstErr := <-done
	if err != nil || n != 1 || firstErr != nil {
		t.Fatalf("concurrent import: n=%d err=%v paused=%v", n, err, firstErr)
	}
	fresh, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if n, err := fresh.ImportArchive(arc); n != 1 || err != nil {
		t.Fatalf("duplicate new blob: n=%d err=%v", n, err)
	}
}

func TestArchiveRejectsDestinationCreatedDuringVerification(t *testing.T) {
	tr, arc, _, _ := existingArchiveFixture(t)
	body := bytes.Repeat([]byte("z"), maxInlineBody+1)
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	raw, err := os.ReadFile(filepath.Join(arc, "traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot ArchiveSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Blobs = append([]string{hash}, snapshot.Blobs...)
	raw, err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(arc, "traffic.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(arc, "blobs", hash+".bin"), body, 0600); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := tr.importArchive(arc, pausedArchiveVerifier(entered, release)); done <- err }()
	<-entered
	tr.record(newFlow("capture.invalid", "GET", "/new", nil, body))
	close(release)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "changed during verification") {
		t.Fatalf("unverified newly appeared destination accepted: %v", err)
	}
	var count int
	if err := tr.DB().QueryRow("SELECT count(*) FROM exchanges WHERE host='archive.invalid'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("import committed: %d %v", count, err)
	}
	if err := tr.DB().QueryRow("SELECT count(*) FROM exchanges WHERE host='capture.invalid'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("capture changed: %d %v", count, err)
	}
	if n, err := tr.ImportArchive(arc); err != nil || n != 1 {
		t.Fatalf("retry after capture: %d %v", n, err)
	}
}

func TestArchivePreverificationUsesSourceLength(t *testing.T) {
	tr, arc, dest, body := existingArchiveFixture(t)
	if err := os.WriteFile(dest, append(body, body...), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	n, err := tr.importArchive(arc, func(path, hash string, length int64) (os.FileInfo, error) {
		called = true
		if length != int64(len(body)) {
			t.Fatalf("expected source length %d, got %d", len(body), length)
		}
		return inspectArchiveBlob(path, hash, length)
	})
	if !called || err == nil || n != 0 || !strings.Contains(err.Error(), "complete regular file") {
		t.Fatalf("oversized destination: called=%v n=%d err=%v", called, n, err)
	}
}
