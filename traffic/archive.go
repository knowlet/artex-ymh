package traffic

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ArchiveSnapshot is the portable traffic subset embedded in one task archive.
// Large content-addressed bodies are copied alongside this manifest rather than
// base64-encoded, preserving deduplication and allowing the tar writer to stream.
type ArchiveSnapshot struct {
	Version   int               `json:"version"`
	Exchanges []ArchiveExchange `json:"exchanges"`
	Blobs     []string          `json:"blobs"`
}

type ArchiveExchange struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	ReqLen      int    `json:"req_len"`
	RespLen     int    `json:"resp_len"`
	ReqHead     string `json:"req_head"`
	ReqBody     []byte `json:"req_body,omitempty"`
	ReqBlob     string `json:"req_blob,omitempty"`
	RespHead    string `json:"resp_head"`
	RespBody    []byte `json:"resp_body,omitempty"`
	RespBlob    string `json:"resp_blob,omitempty"`
}

// ExportHosts writes an exact-host snapshot to dir. It holds the traffic writer
// lock while reading SQLite and blobs, so each body and its index row come from
// one consistent point in time.
func (t *Traffic) ExportHosts(hosts []string, dir string) (int64, error) {
	if t == nil || len(hosts) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return 0, err
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	unique := uniqueArchiveHosts(hosts)
	placeholders := make([]string, len(unique))
	args := make([]any, len(unique))
	for i, host := range unique {
		placeholders[i] = "?"
		args[i] = host
	}
	rows, err := t.db.Query(`SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path
FROM exchanges WHERE host IN (`+strings.Join(placeholders, ",")+`) ORDER BY ts,id`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	snapshot := ArchiveSnapshot{Version: 1}
	blobs := map[string]struct{}{}
	for rows.Next() {
		var item ArchiveExchange
		var legacyPath string
		if err := rows.Scan(&item.ID, &item.TS, &item.Host, &item.Method, &item.URLTemplate,
			&item.URL, &item.Status, &item.ContentType, &item.ReqLen, &item.RespLen, &legacyPath); err != nil {
			return 0, err
		}
		var reqBlob, respBlob sql.NullString
		err := t.db.QueryRow(`SELECT req_head,req_body,req_blob,resp_head,resp_body,resp_blob
FROM exchange_bodies WHERE id=?`, item.ID).Scan(&item.ReqHead, &item.ReqBody, &reqBlob, &item.RespHead, &item.RespBody, &respBlob)
		if errors.Is(err, sql.ErrNoRows) && strings.TrimSpace(legacyPath) != "" {
			req, readErr := os.ReadFile(filepath.Join(t.dir, legacyPath, "request.http"))
			if readErr != nil && !os.IsNotExist(readErr) {
				return 0, readErr
			}
			resp, readErr := os.ReadFile(filepath.Join(t.dir, legacyPath, "response.http"))
			if readErr != nil && !os.IsNotExist(readErr) {
				return 0, readErr
			}
			item.ReqHead, item.RespHead = string(req), string(resp)
		} else if err != nil {
			return 0, err
		}
		item.ReqBlob, item.RespBlob = reqBlob.String, respBlob.String
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				blobs[hash] = struct{}{}
			}
		}
		snapshot.Exchanges = append(snapshot.Exchanges, item)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for hash := range blobs {
		source, err := t.blobPath(hash)
		if err != nil {
			return 0, err
		}
		data, err := os.ReadFile(source)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(filepath.Join(dir, "blobs", hash+".bin"), data, 0o600); err != nil {
			return 0, err
		}
		snapshot.Blobs = append(snapshot.Blobs, hash)
	}
	sort.Strings(snapshot.Blobs)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(dir, "traffic.json"), raw, 0o600); err != nil {
		return 0, err
	}
	return int64(len(snapshot.Exchanges)), nil
}

// ImportArchive imports only missing exchange IDs. Current hot rows always win,
// and repeated restore attempts are safe after a partial external failure.
func (t *Traffic) ImportArchive(dir string) (int64, error) {
	return t.importArchive(dir, inspectArchiveBlob)
}

// The verifier is passed explicitly so concurrency tests can pause a slow read
// without process-global hooks. Production always uses full SHA-256 verification.
func (t *Traffic) importArchive(dir string, inspect func(string, string, int64) (os.FileInfo, error)) (int64, error) {
	if t == nil {
		return 0, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "traffic.json"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var snapshot ArchiveSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return 0, err
	}
	if snapshot.Version != 1 {
		return 0, fmt.Errorf("unsupported traffic archive version %d", snapshot.Version)
	}
	// Hash existing destinations before taking the recording mutex. Supported
	// writers only create or remove canonical blobs, never edit them in place.
	// Keep the verified identity and recheck it under wmu before committing: GC
	// or another import/record may have changed the path during this phase.
	verified := make(map[string]os.FileInfo, len(snapshot.Blobs))
	for _, hash := range snapshot.Blobs {
		if !blobHashRe.MatchString(hash) {
			return 0, fmt.Errorf("invalid archived traffic blob %q", hash)
		}
		if _, seen := verified[hash]; seen {
			continue
		}
		destination := filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin")
		_, err := os.Lstat(destination)
		if os.IsNotExist(err) {
			verified[hash] = nil
			continue
		}
		if err != nil {
			return 0, err
		}
		// Retain the cheap size rejection before reading a damaged destination.
		// The source bytes and length are independently verified under wmu below.
		source, err := os.Stat(filepath.Join(dir, "blobs", hash+".bin"))
		if err != nil {
			return 0, err
		}
		info, err := inspect(destination, hash, source.Size())
		if err != nil {
			return 0, err
		}
		verified[hash] = info
	}
	// Defer reference errors until a row is selected: existing rows and the
	// first archive occurrence still win over ignored duplicate payloads.
	references := make(map[string]archiveReferenceVerification)
	seenIDs := make(map[string]struct{}, len(snapshot.Exchanges))
	for _, item := range snapshot.Exchanges {
		if _, seen := seenIDs[item.ID]; seen {
			continue
		}
		seenIDs[item.ID] = struct{}{}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash == "" {
				continue
			}
			if _, listed := verified[hash]; listed {
				continue
			}
			if _, seen := references[hash]; seen {
				continue
			}
			references[hash] = t.inspectArchiveReference(hash, inspect)
		}
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for _, hash := range snapshot.Blobs {
		if !blobHashRe.MatchString(hash) {
			return 0, fmt.Errorf("invalid archived traffic blob %q", hash)
		}
		data, err := os.ReadFile(filepath.Join(dir, "blobs", hash+".bin"))
		if err != nil {
			return 0, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != hash {
			return 0, fmt.Errorf("traffic blob checksum mismatch: %s", hash)
		}
		destination := filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin")
		if info, err := os.Lstat(destination); err == nil {
			if !sameArchiveBlob(verified[hash], info) || info.Size() != int64(len(data)) {
				return 0, fmt.Errorf("traffic blob changed during verification; retry import: %s", hash)
			}
		} else if !os.IsNotExist(err) {
			return 0, err
		} else {
			if verified[hash] != nil {
				return 0, fmt.Errorf("traffic blob removed during verification; retry import: %s", hash)
			}
			if err := writeArchiveBlob(destination, bytes.NewReader(data), hash, int64(len(data))); err != nil {
				return 0, err
			}
			// Repeated hashes in a manifest may reuse bytes just published under
			// this same writer lock; those source bytes were verified above.
			verified[hash], err = os.Lstat(destination)
			if err != nil {
				return 0, err
			}
		}
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var imported int64
	for _, item := range snapshot.Exchanges {
		res, err := tx.Exec(`INSERT OR IGNORE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`, item.ID, item.TS, item.Host, item.Method, item.URLTemplate,
			item.URL, item.Status, item.ContentType, item.ReqLen, item.RespLen)
		if err != nil {
			return imported, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash == "" {
				continue
			}
			if _, listed := verified[hash]; listed {
				continue
			}
			if err := t.recheckArchiveReference(hash, references[hash]); err != nil {
				return 0, fmt.Errorf("archived exchange %q: %w", item.ID, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, item.ID, item.ReqHead, item.ReqBody, nullIfEmpty(item.ReqBlob),
			item.RespHead, item.RespBody, nullIfEmpty(item.RespBlob)); err != nil {
			return imported, err
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, hash, item.ID); err != nil {
					return imported, err
				}
			}
		}
		if t.fts {
			var rowID int64
			if err := tx.QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, item.ID).Scan(&rowID); err != nil {
				return imported, err
			}
			content := strings.Join([]string{item.URL, item.ReqHead, string(item.ReqBody), item.RespHead, string(item.RespBody)}, "\n")
			if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowID, content); err != nil {
				return imported, err
			}
		}
		imported++
	}
	if err := tx.Commit(); err != nil {
		return imported, err
	}
	return imported, nil
}

// A reference is fully hashed outside wmu, then bound to the same selected
// path and identity under wmu. Errors are retained for selected rows only.
type archiveReferenceVerification struct {
	path string
	info os.FileInfo
	err  error
}

func (t *Traffic) inspectArchiveReference(hash string, inspect func(string, string, int64) (os.FileInfo, error)) archiveReferenceVerification {
	var v archiveReferenceVerification
	if !blobHashRe.MatchString(hash) {
		v.err = fmt.Errorf("invalid archived traffic blob reference %q", hash)
		return v
	}
	v.path, v.err = t.blobPath(hash)
	if v.err != nil {
		return v
	}
	v.info, v.err = os.Lstat(v.path)
	if v.err != nil {
		return v
	}
	v.info, v.err = inspect(v.path, hash, v.info.Size())
	return v
}

// Caller holds wmu; supported writers never edit existing canonical bodies.
func (t *Traffic) recheckArchiveReference(hash string, v archiveReferenceVerification) error {
	if v.err != nil {
		return v.err
	}
	path, err := t.blobPath(hash)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if path != v.path || !sameArchiveBlob(v.info, info) {
		return fmt.Errorf("traffic blob reference changed during verification; retry import: %s", hash)
	}
	return nil
}

// An existing filename is not proof of a complete prior restore. Never replace
// damaged evidence implicitly: fail before committing any exchange metadata.
func verifyArchiveBlob(path, hash string, length int64) error {
	_, err := inspectArchiveBlob(path, hash, length)
	return err
}

// File metadata is not a substitute for hashing: it binds a completed hash to
// the same file at commit time. Hostile in-place writes by unrelated processes
// are outside the store's existing single-writer contract.
func sameArchiveBlob(before, after os.FileInfo) bool {
	return before != nil && after != nil && before.Mode().IsRegular() && after.Mode().IsRegular() &&
		os.SameFile(before, after) && before.Size() == after.Size() &&
		before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}

func inspectArchiveBlob(path, hash string, length int64) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != length {
		return nil, fmt.Errorf("existing traffic blob is not a complete regular file: %s", hash)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !sameArchiveBlob(info, opened) {
		return nil, fmt.Errorf("traffic blob changed before verification: %s", hash)
	}
	sum := sha256.New()
	n, err := io.Copy(sum, f)
	if err != nil {
		return nil, err
	}
	if n != length || hex.EncodeToString(sum.Sum(nil)) != hash {
		return nil, fmt.Errorf("existing traffic blob checksum mismatch: %s", hash)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !sameArchiveBlob(opened, after) {
		return nil, fmt.Errorf("traffic blob changed during verification: %s", hash)
	}
	return after, nil
}

// Stage on the destination filesystem, and publish only after a complete write
// and Sync/Close. A private directory keeps partial bytes out of the blob lookup
// path; OpenFile preserves the old 0644 mode subject to the process umask.
// The caller must hold t.wmu and have verified the source bytes against hash.
func writeArchiveBlob(destination string, body io.Reader, hash string, length int64) error {
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(dir, ".archive-blob-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	path := filepath.Join(stage, "body.bin")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, body)
	if err != nil {
		return err
	}
	if n != length {
		return fmt.Errorf("incomplete archived traffic blob: %s", hash)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Recheck after staging rather than replacing any newly observed bytes.
	// The traffic writer lock serializes supported in-process writers; as with
	// the evidence store, unrelated processes must not mutate this data tree.
	if _, err := os.Lstat(destination); err == nil {
		return verifyArchiveBlob(destination, hash, length)
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(path, destination)
}

func uniqueArchiveHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
