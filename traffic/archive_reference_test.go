package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func archiveReferenceHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func archiveReferenceExchange(id string) ArchiveExchange {
	return ArchiveExchange{
		ID: id, Host: "archive.invalid", Method: "POST", URL: "https://archive.invalid/",
		URLTemplate: "/", Status: 200, ReqHead: "POST / HTTP/1.1", RespHead: "HTTP/1.1 200 OK",
	}
}

func writeArchiveReferenceFixture(t *testing.T, snapshot ArchiveSnapshot, blobs map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "traffic.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for hash, body := range blobs {
		writeArchiveReferenceFile(t, filepath.Join(dir, "blobs", hash+".bin"), body)
	}
	return dir
}

func writeArchiveReferenceFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func archiveReferenceLocalPath(root, hash, layout string) string {
	if layout == "legacy" {
		return filepath.Join(root, "_blobs", "sha256", hash[:2], hash[2:4], hash+".bin")
	}
	return filepath.Join(root, "_blobs", "sha256", hash[:2], hash+".bin")
}

func TestTrafficArchiveRejectsUnresolvedReferences(t *testing.T) {
	for _, side := range []string{"request", "response"} {
		for _, kind := range []string{"missing", "unlisted_source_only", "malformed", "uppercase", "whitespace", "empty", "truncated", "same_length_corrupt", "legacy_corrupt"} {
			t.Run(side+"/"+kind, func(t *testing.T) {
				tr, root := openTraffic(t)
				goodBody := []byte("valid first body")
				goodHash := archiveReferenceHash(goodBody)
				good := archiveReferenceExchange("good-first")
				good.RespBody, good.RespBlob = goodBody, goodHash
				good.RespLen = len(goodBody)
				body := []byte("missing or damaged last body")
				hash := archiveReferenceHash(body)
				files := map[string][]byte{goodHash: goodBody}
				var localPath string
				var corrupt []byte
				switch kind {
				case "unlisted_source_only":
					files[hash] = body
				case "malformed":
					hash = "../not-a-hash"
				case "uppercase", "whitespace":
					// Ordinary blob reads normalize user input, but archive IDs use
					// the same canonical form as the producer and blob_refs GC.
					writeArchiveReferenceFile(t, archiveReferenceLocalPath(root, hash, "current"), body)
					if kind == "uppercase" {
						hash = strings.ToUpper(hash)
					} else {
						hash = " " + hash + " "
					}
				case "empty", "truncated", "same_length_corrupt", "legacy_corrupt":
					layout := "current"
					corrupt = bytes.Repeat([]byte("x"), len(body))
					if kind == "empty" {
						corrupt = []byte{}
					} else if kind == "truncated" {
						corrupt = body[:4]
					} else if kind == "legacy_corrupt" {
						layout = "legacy"
					}
					localPath = archiveReferenceLocalPath(root, hash, layout)
					writeArchiveReferenceFile(t, localPath, corrupt)
				}
				bad := archiveReferenceExchange("bad-last")
				if side == "request" {
					bad.ReqBlob, bad.ReqLen = hash, len(body)
				} else {
					bad.RespBlob, bad.RespLen = hash, len(body)
				}
				dir := writeArchiveReferenceFixture(t, ArchiveSnapshot{
					Version: 1, Blobs: []string{goodHash}, Exchanges: []ArchiveExchange{good, bad},
				}, files)
				count, err := tr.ImportArchive(dir)
				if err == nil || count != 0 {
					t.Errorf("unresolved reference accepted: imported=%d err=%v", count, err)
				}
				tables := []string{"exchanges", "exchange_bodies", "blob_refs"}
				if tr.fts {
					tables = append(tables, "ex_fts")
				}
				for _, table := range tables {
					var rows int
					if err := tr.DB().QueryRow(`SELECT count(*) FROM ` + table).Scan(&rows); err != nil || rows != 0 {
						t.Errorf("failed import committed %s rows=%d err=%v", table, rows, err)
					}
				}
				if localPath != "" {
					got, err := os.ReadFile(localPath)
					if err != nil || !bytes.Equal(got, corrupt) {
						t.Fatalf("damaged local bytes changed: got=%q err=%v", got, err)
					}
				}
			})
		}
	}
}

func TestTrafficArchiveReusesUnlistedLocalReferences(t *testing.T) {
	body := []byte("valid shared local request and response")
	hash := archiveReferenceHash(body)
	for _, layout := range []string{"current", "legacy"} {
		t.Run(layout, func(t *testing.T) {
			tr, root := openTraffic(t)
			path := archiveReferenceLocalPath(root, hash, layout)
			writeArchiveReferenceFile(t, path, body)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			first := archiveReferenceExchange("local-first")
			first.ReqBlob, first.RespBlob = hash, hash
			first.ReqLen, first.RespLen = len(body), len(body)
			second := first
			second.ID = "local-second"
			dir := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{first, second}}, nil)
			if count, err := tr.ImportArchive(dir); count != 2 || err != nil {
				t.Fatalf("local import count=%d err=%v", count, err)
			}
			if count, err := tr.ImportArchive(dir); count != 0 || err != nil {
				t.Fatalf("idempotent import count=%d err=%v", count, err)
			}
			err = tr.ReadEvidence(context.Background(), []string{first.ID, second.ID}, func(e EvidenceExchange) error {
				for _, reader := range []io.Reader{e.Request, e.Response} {
					got, err := io.ReadAll(reader)
					if err != nil || !bytes.Equal(got, body) {
						t.Fatalf("local body=%q err=%v", got, err)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatalf("valid local file modified: err=%v", err)
			}
			var refs int
			if err := tr.DB().QueryRow(`SELECT count(*) FROM blob_refs WHERE hash=?`, hash).Scan(&refs); err != nil || refs != 2 {
				t.Fatalf("shared refs=%d err=%v", refs, err)
			}
		})
	}
}

func TestTrafficArchiveIgnoresDuplicateReferences(t *testing.T) {
	for _, kind := range []string{"current_row", "first_archive_row"} {
		t.Run(kind, func(t *testing.T) {
			tr, _ := openTraffic(t)
			good := archiveReferenceExchange("duplicate-exchange")
			good.RespBody = []byte("current body wins")
			bad := archiveReferenceExchange(good.ID)
			bad.ReqBlob, bad.RespBlob = "../invalid", archiveReferenceHash([]byte("absent"))
			items, want := []ArchiveExchange{good, bad}, int64(1)
			if kind == "current_row" {
				seed := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{good}}, nil)
				if count, err := tr.ImportArchive(seed); count != 1 || err != nil {
					t.Fatalf("seed count=%d err=%v", count, err)
				}
				items, want = []ArchiveExchange{bad}, 0
			}
			dir := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: items}, nil)
			if count, err := tr.ImportArchive(dir); count != want || err != nil {
				t.Fatalf("duplicate import count=%d err=%v", count, err)
			}
			_, resp, err := tr.Get(good.ID)
			if err != nil || !strings.Contains(resp, "current body wins") || strings.Contains(resp, "@blob") {
				t.Fatalf("current body replaced: resp=%q err=%v", resp, err)
			}
			var refs int
			if err := tr.DB().QueryRow(`SELECT count(*) FROM blob_refs`).Scan(&refs); err != nil || refs != 0 {
				t.Fatalf("ignored references inserted: refs=%d err=%v", refs, err)
			}
		})
	}
}

func TestTrafficArchiveRejectsNonRegularUnlistedLocalReference(t *testing.T) {
	for _, kind := range []string{"directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			tr, root := openTraffic(t)
			body := []byte("local body")
			hash := archiveReferenceHash(body)
			path := archiveReferenceLocalPath(root, hash, "current")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if kind == "directory" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				target := filepath.Join(t.TempDir(), "body.bin")
				writeArchiveReferenceFile(t, target, body)
				err := os.Symlink(target, path)
				if runtime.GOOS == "windows" && (errors.Is(err, os.ErrPermission) ||
					errors.Is(err, syscall.Errno(1314)) || errors.Is(err, syscall.Errno(50))) {
					t.Skipf("Windows symlink fixture unavailable (privilege or filesystem support): %v", err)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			e := archiveReferenceExchange("non-regular-reference")
			e.RespBlob = hash
			dir := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{e}}, nil)
			if count, err := tr.ImportArchive(dir); count != 0 || err == nil {
				t.Fatalf("non-regular local blob accepted: count=%d err=%v", count, err)
			}
			if count, err := tr.Count(); count != 0 || err != nil {
				t.Fatalf("failed import committed rows=%d err=%v", count, err)
			}
		})
	}
}
