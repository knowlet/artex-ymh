package server

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecuritySkillMetadataMemory(t *testing.T) {
	// Exercise the real metadata rewriter on small inputs. A line table or one
	// key/value record per tiny line used to multiply these allocations, even
	// though the ZIP upload's name parser already avoided that amplification.
	const fixtureBytes = 64 << 10
	const header = "---\nname: memory-skill\n"
	const body = "body\r\n\n"
	tests := []struct {
		name    string
		content []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "newline-heavy body",
			content: []byte(header + "---\n" + strings.Repeat("\n", fixtureBytes) + body),
			want:    []byte(header + "---\n" + strings.Repeat("\n", fixtureBytes) + body),
		},
		{
			name:    "newline-heavy frontmatter",
			content: []byte("---\n" + strings.Repeat("\n", fixtureBytes) + "name: memory-skill\n---\n" + body),
			want:    []byte(header + "---\n" + body),
		},
		{
			name:    "tiny frontmatter keys",
			content: []byte(header + strings.Repeat("a:\n", fixtureBytes/3) + "---\n" + body),
			want:    []byte(header + strings.Repeat("a: \n", fixtureBytes/3) + "---\n" + body),
		},
		{
			name:    "tiny empty frontmatter keys",
			content: []byte(header + strings.Repeat(":\n", fixtureBytes/2) + "---\n" + body),
			want:    []byte(header + strings.Repeat("\n", fixtureBytes/2) + "---\n" + body),
		},
		{
			name:    "malformed opening",
			content: []byte("not frontmatter\n" + strings.Repeat("\n", fixtureBytes)),
			wantErr: true,
		},
		{
			name:    "unclosed frontmatter",
			content: []byte(header + strings.Repeat("\n", fixtureBytes)),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rewriteSkillFrontmatter(tt.content, nil, nil, nil, nil)
			if (err != nil) != tt.wantErr || !bytes.Equal(got, tt.want) {
				t.Fatalf("unexpected rewrite: error=%v, output bytes=%d, want error=%t, want bytes=%d", err, len(got), tt.wantErr, len(tt.want))
			}
			result := testing.Benchmark(func(b *testing.B) {
				for b.Loop() {
					got, err := rewriteSkillFrontmatter(tt.content, nil, nil, nil, nil)
					if (err != nil) != tt.wantErr || !bytes.Equal(got, tt.want) {
						b.Fatal("metadata rewrite changed while measuring allocations")
					}
				}
			})
			// Allow output storage, bounded buffer growth, and a small fixed
			// overhead; do not allow allocation proportional to line headers.
			limit := int64(4*len(tt.content) + 8<<10)
			allocated := result.AllocedBytesPerOp()
			t.Logf("input=%d bytes, allocated=%d bytes/op, limit=%d bytes/op", len(tt.content), allocated, limit)
			if allocated > limit {
				t.Fatalf("metadata rewrite allocates %d bytes for %d-byte input (limit %d)", allocated, len(tt.content), limit)
			}
		})
	}
}

func TestSecuritySkillMetadataCompatibility(t *testing.T) {
	str := func(v string) *string { return &v }
	list := func(v ...string) *[]string { return &v }
	tests := []struct {
		name          string
		content       string
		mcps          *[]string
		description   *string
		license       *string
		compatibility *string
		want          string
	}{
		{
			name:    "nil fields preserve values and unknown order",
			content: " \t--- \r\nname : demo\r\nunknown-z : last \r\n\r\ndescription: old description\r\nlicense: old license\r\ncompatibility: old compatibility\r\nmcps: first\r\nunknown-a: before:after\r\nmcps: second\r\n--- \r\nbody\n\n",
			want:    "---\nname: demo\nunknown-z: last\ndescription: old description\nlicense: old license\ncompatibility: old compatibility\nmcps: first\nunknown-a: before:after\nmcps: second\n---\nbody\n\n",
		},
		{
			name:          "only first duplicate string field changes",
			content:       "---\ndescription: first\nunknown: between\ndescription: second\nlicense: first\nlicense: second\ncompatibility: first\ncompatibility: second\n---\nbody",
			description:   str(" refreshed "),
			license:       str(" revised "),
			compatibility: str(" updated "),
			want:          "---\ndescription: refreshed\nunknown: between\ndescription: second\nlicense: revised\nlicense: second\ncompatibility: updated\ncompatibility: second\n---\nbody",
		},
		{
			name:          "explicit empty strings clear existing values",
			content:       "---\nname: demo\ndescription: old\nlicense: MIT\ncompatibility: old runtime\n---\nbody\n",
			description:   str(" \t "),
			license:       str(""),
			compatibility: str("\r\n"),
			want:          "---\nname: demo\ndescription: \nlicense: \ncompatibility: \n---\nbody\n",
		},
		{
			name:          "missing string fields append in established order",
			content:       "---\nunknown: keep\nname: demo\n---\n",
			mcps:          list(" browser "),
			description:   str(" new description "),
			license:       str(""),
			compatibility: str(" new runtime "),
			want:          "---\nunknown: keep\nname: demo\ndescription: new description\nlicense: \ncompatibility: new runtime\nmcps: browser\n---\n",
		},
		{
			name:    "mcps replaces all entries and retains configured duplicates",
			content: "---\nmcps: old first\nname: demo\nunknown: keep\nmcps: old second\n---\nbody\n",
			mcps:    list(" browser ", "", " proxy ", "browser", "\t"),
			want:    "---\nname: demo\nunknown: keep\nmcps: browser, proxy, browser\n---\nbody\n",
		},
		{
			name:    "empty mcps removes all entries",
			content: "---\nmcps: first\nname: demo\nmcps: second\n---\nbody\n",
			mcps:    list(),
			want:    "---\nname: demo\n---\nbody\n",
		},
		{
			name:    "blank mcps removes all entries",
			content: "---\nmcps: first\nname: demo\nmcps: second\n---\nbody\n",
			mcps:    list(" ", "\t"),
			want:    "---\nname: demo\n---\nbody\n",
		},
		{
			name:    "raw nonkey lines and body CRLF survive",
			content: "---\r\nname: demo\r\n  # comment without colon \r\n  |\r\n : odd value \r\n\t\r\n---\r\nBody \r\n\r\n\nEOF\r\n",
			want:    "---\nname: demo\n  # comment without colon \r\n  |\r\nodd value\n---\nBody \r\n\r\n\nEOF\r\n",
		},
		{
			name:    "closing delimiter at EOF",
			content: "---\nname: demo\n---",
			want:    "---\nname: demo\n---\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rewriteSkillFrontmatter([]byte(tt.content), tt.mcps, tt.description, tt.license, tt.compatibility)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("rewrite = %q\nwant    = %q", got, tt.want)
			}
		})
	}
}

func TestSecurityUploadedSkillMetadataPreservesBody(t *testing.T) {
	const name = "metadata-fixture"
	// The data reaches metadata editing through the real ZIP upload handler,
	// including a compressible body, mixed newlines, and an untouched unknown key.
	body := strings.Repeat("\n", 64<<10) + "Instructions\r\n  preserve this spacing\n\n"
	original := "---\nname: " + name + "\ndescription: original\nunknown: keep\ncompatibility: retained\nmcps: old\n---\n" + body
	dir := t.TempDir()
	rr, out := uploadZip(t, dir, "metadata-fixture.zip", buildZip(t,
		zipFile{name: "bundle/SKILL.md", body: original, method: zip.Deflate},
	))
	if rr.Code != http.StatusCreated || out["name"] != name {
		t.Fatalf("upload status=%d, response=%s", rr.Code, rr.Body.String())
	}
	request := httptest.NewRequest(http.MethodPut, "/api/skills/"+name+"/meta", strings.NewReader(`{"description":" refreshed ","license":"","mcps":[" browser ","","proxy"]}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("name", name)
	rr = httptest.NewRecorder()
	(&Server{skillDir: dir}).fsUpdateSkillMeta(rr, request)
	if rr.Code != http.StatusOK {
		t.Fatalf("metadata status=%d, response=%s", rr.Code, rr.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, name, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "---\nname: " + name + "\ndescription: refreshed\nunknown: keep\ncompatibility: retained\nlicense: \nmcps: browser, proxy\n---\n" + body
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("uploaded skill metadata/body changed unexpectedly: got %d bytes, want %d", len(got), len(want))
	}
}
