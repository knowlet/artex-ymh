package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSecurityBrowserEnvNullIsWritable(t *testing.T) {
	for _, raw := range []string{"null", "", "[]", `{"PATH":null}`, `{broken`} {
		env := decodeStrMap(json.RawMessage(raw))
		// syncBrowserMCPProxy sets this field when traffic capture is enabled.
		env["NODE_EXTRA_CA_CERTS"] = "/tmp/test-ca.pem"
		if env["NODE_EXTRA_CA_CERTS"] != "/tmp/test-ca.pem" {
			t.Fatalf("unwritable environment for %q", raw)
		}
	}
	env := decodeStrMap(json.RawMessage(`{"PATH":"/usr/bin","EXPLICIT":"configured"}`))
	if env["PATH"] != "/usr/bin" || env["EXPLICIT"] != "configured" {
		t.Fatal("valid configured environment was lost")
	}
}

func TestSecurityAssetInsertRequestLimits(t *testing.T) {
	// No SQL connection: rejection must occur before any asset write.
	s := &Server{m: &Manager{pg: &db.DB{}}}
	tests := []struct {
		name, body string
		status     int
	}{
		{"large field", `{"assets":[],"ignored":"` + strings.Repeat("x", 2<<20) + `"}`, 413},
		{"large suffix", `{"assets":[]}` + strings.Repeat(" ", 2<<20), 413},
		{"batch", `{"assets":[` + strings.Repeat(`{"type":"unknown"},`, 1000) + `{"type":"unknown"}]}`, 400},
		{"extra JSON", `{"assets":[]} {"assets":[]}`, 400},
		{"empty legitimate batch", `{"assets":[]}`, 200},
		{"bounded batch errors", `{"assets":[{"type":"unknown"}]}`, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.insertAssets(w, httptest.NewRequest("POST", "/api/assets", strings.NewReader(tt.body)))
			if w.Code != tt.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tt.status, w.Body.String())
			}
		})
	}
}

func TestSecurityConversationMessageLimits(t *testing.T) {
	// A valid request reaches the unavailable-DB response; oversized requests
	// must be rejected before conversation lookup or agent startup.
	s := &Server{m: &Manager{}}
	tests := []struct {
		name, body string
		status     int
	}{
		{"large message", `{"message":"` + strings.Repeat("x", 2<<20) + `"}`, 413},
		{"large ignored field", `{"message":"hello","extra":"` + strings.Repeat("x", 2<<20) + `"}`, 413},
		{"large suffix", `{"message":"hello"}` + strings.Repeat(" ", 2<<20), 413},
		{"attachment count", `{"attachments":[` + strings.Repeat(`{"path":"uploads/a.txt"},`, 32) + `{"path":"uploads/b.txt"}]}`, 400},
		{"extra JSON", `{"message":"hello"} {}`, 400},
		{"valid message", `{"message":"hello"}`, 503},
		{"valid attachment", `{"attachments":[{"name":"a.txt","path":"uploads/a.txt","size":12}]}`, 503},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/conversations/1/messages", strings.NewReader(tt.body))
			r.SetPathValue("id", "1")
			s.pgSendConversationMessage(w, r)
			if w.Code != tt.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tt.status, w.Body.String())
			}
		})
	}
}

func TestSecurityScopeSyncLimitsBeforeNetwork(t *testing.T) {
	s := &Server{m: &Manager{pg: &db.DB{}}}
	bodies := []struct {
		body string
		code int
	}{
		{`{"dimension":"task","targets":["a"],"extra":"` + strings.Repeat("x", 64<<10) + `"}`, 413},
		{`{"dimension":"task","targets":["a"]}` + strings.Repeat(" ", 64<<10), 413},
		{`{"dimension":"task","targets":[` + strings.Repeat(`"a",`, 100) + `"a"]}`, 400},
		{`{"dimension":"task","targets":["a"],"asset_types":["app","app","app","app"]}`, 400},
		{`{"dimension":"task","targets":["a"],"asset_types":["unknown"]}`, 400},
		{`{"dimension":"task","targets":[" "]}`, 400},
		{`{"dimension":"task","targets":["a"]} {}`, 400},
	}
	for i, tt := range bodies {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w := httptest.NewRecorder()
			s.syncSSRun(w, httptest.NewRequest("POST", "/api/sync/scopesentry/sync", strings.NewReader(tt.body)))
			if w.Code != tt.code {
				t.Fatalf("status=%d want=%d", w.Code, tt.code)
			}
		})
	}
	req := ssSyncReq{Dimension: "project", Targets: []string{"a", " a ", "b"}, AssetTypes: []string{"app", "service", "app"}}
	if err := req.validate(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(req.Targets, ",") != "a,b" || strings.Join(req.AssetTypes, ",") != "app,service" {
		t.Fatalf("duplicate work survived: %+v", req)
	}
	req = ssSyncReq{Dimension: "task", Targets: []string{"normal task"}}
	if err := req.validate(); err != nil || len(req.AssetTypes) != 3 {
		t.Fatalf("default types rejected: %+v, %v", req, err)
	}
}

func TestSecurityRecordPageHTTPRejectsBeforeSQL(t *testing.T) {
	s := &Server{m: &Manager{pg: &db.DB{}}}
	for name, handler := range map[string]http.HandlerFunc{"commands": s.pgListCommands, "llm": s.pgListLLMRecords} {
		for _, size := range []string{"201", "1000000"} {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest("GET", "/api/"+name+"?size="+size, nil))
			if w.Code != 400 {
				t.Fatalf("%s size=%s: status=%d", name, size, w.Code)
			}
		}
	}
}

func TestSecuritySkillFrontmatterMemory(t *testing.T) {
	// A newline-heavy, well-compressible input used to allocate a string header
	// for every byte. Measure allocations without approaching an OOM condition.
	md := append(bytes.Repeat([]byte{'\n'}, 64<<10), []byte("---\nname: \"中文技能\"\n---\nbody")...)
	if got := skillNameFromFrontmatter(md); got != "中文技能" {
		t.Fatalf("name=%q", got)
	}
	result := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			if skillNameFromFrontmatter(md) != "中文技能" {
				b.Fatal("name changed")
			}
		}
	})
	if got := result.AllocedBytesPerOp(); got > 4096 {
		t.Fatalf("frontmatter scan allocates %d bytes for newline-heavy input", got)
	}
	// Reject declared oversized SKILL.md before opening/decompressing it.
	f := &zip.File{FileHeader: zip.FileHeader{UncompressedSize64: (20 << 20) + 1}}
	if _, err := readZipEntry(f); err == nil {
		t.Fatal("oversized ZIP member accepted")
	}
	z := buildZip(t, zipFile{name: "SKILL.md", body: "---\nname: safe-skill\n---\nhello", method: zip.Deflate})
	zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		t.Fatal(err)
	}
	data, err := readZipEntry(zr.File[0])
	if err != nil || !bytes.Contains(data, []byte("safe-skill")) {
		t.Fatalf("valid ZIP failed: %v", err)
	}
}
