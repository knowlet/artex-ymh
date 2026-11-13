package traffic

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// preReqPathIndexSchema is the exchanges table before req_path (release ≤ round-3).
const preReqPathIndexSchema = `
CREATE TABLE IF NOT EXISTS exchanges (
  id           TEXT PRIMARY KEY,
  ts           INTEGER,
  host         TEXT,
  method       TEXT,
  url_template TEXT,
  url          TEXT,
  status       INTEGER,
  content_type TEXT,
  req_len      INTEGER,
  resp_len     INTEGER,
  path         TEXT
);
CREATE TABLE IF NOT EXISTS exchange_bodies (
  id        TEXT PRIMARY KEY,
  req_head  TEXT NOT NULL DEFAULT '',
  req_body  BLOB,
  req_blob  TEXT,
  resp_head TEXT NOT NULL DEFAULT '',
  resp_body BLOB,
  resp_blob TEXT
);
`

func openPreReqPathIndex(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "_index"), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "_index", "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, p := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(preReqPathIndexSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES ('leg1',100,'h','GET','/users/{id}','http://h/users/42',200,'text/plain',0,0,'')`); err != nil {
		t.Fatal(err)
	}
}

func TestOpenIndexReadOnlyLegacySchema(t *testing.T) {
	dir := t.TempDir()
	openPreReqPathIndex(t, dir)
	tr, err := OpenIndexReadOnly(dir)
	if err != nil {
		t.Fatalf("OpenIndexReadOnly legacy: %v", err)
	}
	defer tr.Close()
	var reqPath string
	if err := tr.db.QueryRow(`SELECT req_path FROM exchanges WHERE id='leg1'`).Scan(&reqPath); err != nil {
		t.Fatal(err)
	}
	if reqPath != "/users/42" {
		t.Fatalf("migration backfill req_path: got %q", reqPath)
	}
	step := "GET /users/42 HTTP/1.1\nHost: h\n\n"
	if id, ok := tr.ResolveStepExchange(step, ""); !ok || id != "leg1" {
		t.Fatalf("legacy exchange link: want leg1/true, got %q/%v", id, ok)
	}
}

func TestReproductionLinksAfterReqPathBackfill(t *testing.T) {
	dir := t.TempDir()
	openPreReqPathIndex(t, dir)
	if err := migrateIndexFile(dir); err != nil {
		t.Fatal(err)
	}
	tr, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	step := "GET /users/42 HTTP/1.1\nHost: h\n\n"
	if id, ok := tr.ResolveStepExchange(step, ""); !ok || id != "leg1" {
		t.Fatalf("after backfill: want leg1/true, got %q/%v", id, ok)
	}
}
