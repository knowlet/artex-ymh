package traffic

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestArchiveReferenceReimportSkipsHash(t *testing.T) {
	tr, root := openTraffic(t)
	body := []byte("existing unlisted body")
	hash := archiveReferenceHash(body)
	writeArchiveReferenceFile(t, archiveReferenceLocalPath(root, hash, "current"), body)
	e := archiveReferenceExchange("existing-reference")
	e.RespBlob = hash
	e.RespLen = len(body)
	arc := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{e}}, nil)
	if n, err := tr.ImportArchive(arc); err != nil || n != 1 {
		t.Fatalf("seed %d %v", n, err)
	}
	calls := 0
	n, err := tr.importArchive(arc, func(path, hash string, length int64) (os.FileInfo, error) {
		calls++
		return inspectArchiveBlob(path, hash, length)
	})
	if err != nil || n != 0 || calls != 0 {
		t.Fatalf("reimport n=%d calls=%d err=%v", n, calls, err)
	}
}

func TestArchiveReferenceStalePreflightRequiresRetry(t *testing.T) {
	for _, kind := range []string{"deleted_row", "newly_available_body"} {
		t.Run(kind, func(t *testing.T) {
			tr, root := openTraffic(t)
			body := []byte("first reference")
			hash := archiveReferenceHash(body)
			path := archiveReferenceLocalPath(root, hash, "current")
			first := archiveReferenceExchange("first")
			first.RespBlob = hash
			first.RespLen = len(body)
			if kind == "deleted_row" {
				writeArchiveReferenceFile(t, path, body)
				seed := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{first}}, nil)
				if _, err := tr.ImportArchive(seed); err != nil {
					t.Fatal(err)
				}
			}
			otherBody := []byte("second reference")
			otherHash := archiveReferenceHash(otherBody)
			writeArchiveReferenceFile(t, archiveReferenceLocalPath(root, otherHash, "current"), otherBody)
			second := archiveReferenceExchange("second")
			second.RespBlob = otherHash
			second.RespLen = len(otherBody)
			arc := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{first, second}}, nil)
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			go func() { _, err := tr.importArchive(arc, pausedArchiveVerifier(entered, release)); done <- err }()
			select {
			case <-entered:
			case err := <-done:
				close(release)
				t.Fatalf("early return %v", err)
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("verification not entered")
			}
			tr.wmu.Lock()
			var mutationErr error
			if kind == "deleted_row" {
				// Model deletion of the existing row while retaining its shared blob.
				for _, table := range []string{"blob_refs", "exchange_bodies", "exchanges"} {
					column := "id"
					if table == "blob_refs" {
						column = "exchange_id"
					}
					if _, err := tr.DB().Exec("DELETE FROM "+table+" WHERE "+column+"=?", first.ID); err != nil {
						mutationErr = err
						break
					}
				}
			} else {
				writeArchiveReferenceFile(t, path, body)
			}
			tr.wmu.Unlock()
			close(release)
			err := <-done
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			if err == nil || !strings.Contains(err.Error(), "retry import") {
				t.Fatalf("expected explicit retry: %v", err)
			}
			var n int
			if err := tr.DB().QueryRow("SELECT count(*) FROM exchanges").Scan(&n); err != nil || n != 0 {
				t.Fatalf("partial commit %d %v", n, err)
			}
			if n, err := tr.ImportArchive(arc); err != nil || n != 2 {
				t.Fatalf("retry n=%d err=%v", n, err)
			}
		})
	}
}

func TestArchiveReferenceRejectsLengthMismatch(t *testing.T) {
	for _, layout := range []string{"listed", "current", "legacy"} {
		for _, side := range []string{"request", "response"} {
			for _, length := range []int{-1, 0, 3, 100} {
				t.Run(layout+"/"+side+"/"+fmt.Sprint(length), func(t *testing.T) {
					tr, root := openTraffic(t)
					body := []byte("full body")
					hash := archiveReferenceHash(body)
					good := archiveReferenceExchange("good")
					good.RespBody = []byte("inline remains compatible")
					bad := archiveReferenceExchange("bad")
					if side == "request" {
						bad.ReqBlob = hash
						bad.ReqLen = length
					} else {
						bad.RespBlob = hash
						bad.RespLen = length
					}
					snapshot := ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{good, bad}}
					var files map[string][]byte
					if layout == "listed" {
						snapshot.Blobs = []string{hash}
						files = map[string][]byte{hash: body}
					} else {
						writeArchiveReferenceFile(t, archiveReferenceLocalPath(root, hash, layout), body)
					}
					arc := writeArchiveReferenceFixture(t, snapshot, files)
					if n, err := tr.ImportArchive(arc); n != 0 || err == nil || !strings.Contains(err.Error(), "length") {
						t.Fatalf("accepted length n=%d err=%v", n, err)
					}
					var n int
					if err := tr.DB().QueryRow("SELECT count(*) FROM exchanges").Scan(&n); err != nil || n != 0 {
						t.Fatalf("partial commit %d %v", n, err)
					}
				})
			}
		}
	}
}

func TestArchiveReferenceEmptyBlobAndIgnoredLength(t *testing.T) {
	tr, _ := openTraffic(t)
	hash := archiveReferenceHash(nil)
	first := archiveReferenceExchange("empty-reference")
	first.ReqBlob = hash
	first.RespBlob = hash
	bad := first
	bad.ReqLen = -1
	bad.RespLen = 100
	arc := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Blobs: []string{hash}, Exchanges: []ArchiveExchange{first, bad}}, map[string][]byte{hash: nil})
	if n, err := tr.ImportArchive(arc); n != 1 || err != nil {
		t.Fatalf("valid empty blob rejected n=%d err=%v", n, err)
	}
	retry := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{bad}}, nil)
	if n, err := tr.ImportArchive(retry); n != 0 || err != nil {
		t.Fatalf("ignored row length checked n=%d err=%v", n, err)
	}
}
