package intelpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureDate = "2026-10-23T19:30:18Z"

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	commit, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	catalog := kevCatalog{
		SchemaVersion: 1, CatalogVersion: "2026.10.23", DateReleased: fixtureDate,
		Count: 2, License: "CC0-1.0", LicenseURL: "https://github.com/cisagov/kev-data/blob/" + commit + "/LICENSE", Scope: "CISA KEV only; not the complete CVE List",
		Source: Source{Kind: "official-github", Repository: "cisagov/kev-data", Commit: commit, SHA256: digest, URL: "https://raw.githubusercontent.com/cisagov/kev-data/" + commit + "/known_exploited_vulnerabilities.json"},
		Vulnerabilities: []Vulnerability{
			{CVEID: "CVE-2026-12345", VendorProject: "Example", Product: "Gateway", VulnerabilityName: "Gateway input issue", ShortDescription: "Input validation issue", RequiredAction: "Apply vendor fix", DateAdded: "2026-10-22", DueDate: "2026-11-01", CWEs: []string{"CWE-20"}},
			{CVEID: "CVE-2026-12346", VendorProject: "Example", Product: "Agent", VulnerabilityName: "Agent issue", ShortDescription: "Transport issue", RequiredAction: "Apply vendor fix", DateAdded: "2026-10-23", DueDate: "2026-11-02"},
		},
	}
	lock := releaseLock{SchemaVersion: 1}
	for _, name := range []string{"nuclei", "httpx", "naabu", "katana", "subfinder", "nuclei-templates"} {
		base := "https://github.com/projectdiscovery/" + name
		row := releaseTool{Tool: Tool{Name: name, Version: "v1.2.3", Commit: commit, ReleasedAt: fixtureDate}, Repository: "projectdiscovery/" + name, License: "MIT", ReleaseURL: base + "/releases/tag/v1.2.3", SourceURL: base + "/tree/" + commit}
		row.Assets = append(row.Assets, struct {
			Name   string `json:"name"`
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
		}{Name: "checksums.txt", URL: base + "/releases/download/v1.2.3/checksums.txt", SHA256: digest})
		lock.Tools = append(lock.Tools, row)
	}
	x := templateIndex{SchemaVersion: 1, License: "MIT", LicenseFile: "discovery/NUCLEI-LICENSE.txt", Count: 3, UniqueCVECount: 2}
	x.Source.Source = Source{Kind: "official-github", Repository: "projectdiscovery/nuclei-templates", Commit: commit, SHA256: digest, URL: "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/" + commit + "/cves.json"}
	x.Source.BlobSHA, x.Source.Release, x.Source.PublishedAt = commit, "v1.2.3", fixtureDate
	x.Templates = []Template{
		{CVEID: "CVE-2026-12345", TemplateID: "CVE-2026-12345-check", Title: "Gateway input issue", Severity: "high", Path: "http/cves/2026/gateway.yaml", Protocol: "http"},
		{CVEID: "CVE-2026-12345", TemplateID: "CVE-2026-12345-info", Title: "Gateway info", Severity: "info", Path: "http/cves/2026/gateway-info.yaml", Protocol: "http"},
		{CVEID: "CVE-2026-99999", TemplateID: "CVE-2026-99999-check", Title: "Other candidate", Severity: "medium", Path: "http/cves/2026/other.yaml", Protocol: "http"},
	}
	writeJSON(t, filepath.Join(root, "vulnerability-intel.json"), catalog)
	writeJSON(t, filepath.Join(root, "projectdiscovery-lock.json"), lock)
	writeJSON(t, filepath.Join(root, "nuclei-cve-index.json"), x)
	if err := os.Mkdir(filepath.Join(root, "discovery"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "discovery/NUCLEI-LICENSE.txt"), []byte("MIT License\nPermission is hereby granted, free of charge\nThe above copyright notice and this permission notice shall be included\nTHE SOFTWARE IS PROVIDED \"AS IS\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bind(t, root)
	return filepath.Join(root, "discovery-data-manifest.json")
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func bind(t *testing.T, root string) {
	t.Helper()
	m := Manifest{SchemaVersion: 1, Kind: packKind, Scope: packScope}
	for _, f := range []File{{Name: "cisa-kev", Path: "vulnerability-intel.json", License: "CC0-1.0"}, {Name: "projectdiscovery-releases", Path: "projectdiscovery-lock.json", License: "MIT"}, {Name: "nuclei-cve-index", Path: "nuclei-cve-index.json", License: "MIT"}} {
		raw, err := os.ReadFile(filepath.Join(root, f.Path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		f.Bytes, f.SHA256, f.SourceDate = int64(len(raw)), hex.EncodeToString(sum[:]), fixtureDate
		m.Files = append(m.Files, f)
	}
	writeJSON(t, filepath.Join(root, "discovery-data-manifest.json"), m)
}

func TestLoadStatusAndOfflineAge(t *testing.T) {
	p, err := Load(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	published, _ := time.Parse(time.RFC3339Nano, fixtureDate)
	status := p.Status(published.Add(48 * time.Hour))
	if status.AgeSeconds != 172800 || status.KEVCount != 2 || status.TemplateCount != 3 || status.Freshness != "not-checked-online" || len(status.Tools) != 6 {
		t.Fatalf("bad status: %+v", status)
	}
	if !p.Status(published.Add(-time.Hour)).TimestampInFuture {
		t.Fatal("future timestamp concealed")
	}
	status.Tools[0].Version = "mutated"
	if p.Status(published).Tools[0].Version == "mutated" {
		t.Fatal("status exposes mutable internal slice")
	}
}

func TestSearchFiltersAndBounds(t *testing.T) {
	p, err := Load(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Search(Query{Vendor: "eXAmple", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 2 || r.Returned != 1 || !r.Truncated || len(r.Matches) != 1 || r.TemplateTotal != 2 || len(r.TemplateMatches) != 1 || !r.TemplateTruncated || r.TargetVulnerability != "unverified" {
		t.Fatalf("bad search %+v", r)
	}
	r, err = p.Search(Query{Vendor: "Example", Product: "Gateway", Text: "INPUT"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 1 || r.TemplateTotal != 2 || r.Limit != DefaultLimit {
		t.Fatalf("AND filters failed: %+v", r)
	}
	r, err = p.Search(Query{CVE: "cve-2026-99999"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 0 || r.TemplateTotal != 1 || r.TemplateMatches[0].CVEID != "CVE-2026-99999" {
		t.Fatalf("index-only CVE concealed: %+v", r)
	}
	r, err = p.Search(Query{CVE: "CVE-2026-99999", Vendor: "Example"})
	if err != nil {
		t.Fatal(err)
	}
	if r.TemplateTotal != 0 {
		t.Fatal("template results ignored AND vendor constraint")
	}
	for _, q := range []Query{{}, {Text: " "}, {CVE: "CVE-2026-*"}, {Text: "x", Limit: -1}, {Text: "x", Limit: 101}, {Text: strings.Repeat("x", 1025)}} {
		if _, err := p.Search(q); err == nil {
			t.Fatalf("accepted invalid query: %+v", q)
		}
	}
	r, err = p.Search(Query{CVE: "CVE-2026-0000"})
	if err != nil || r.Total != 0 || r.TemplateTotal != 0 {
		t.Fatal("zero matches should be valid")
	}
}

func TestSearchDoesNotExposeMutableRecords(t *testing.T) {
	p, err := Load(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := p.Search(Query{CVE: "CVE-2026-12345"})
	r.Matches[0].CWEs[0] = "changed"
	r2, _ := p.Search(Query{CVE: "CVE-2026-12345"})
	if r2.Matches[0].CWEs[0] != "CWE-20" {
		t.Fatal("query result mutates pack")
	}
}

func TestHashMismatchAndMissingFilesFailClosed(t *testing.T) {
	for _, mode := range []string{"tamper", "missing", "empty", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			manifest := fixture(t)
			target := filepath.Join(filepath.Dir(manifest), "vulnerability-intel.json")
			switch mode {
			case "tamper":
				os.WriteFile(target, []byte("{}"), 0o600)
			case "missing":
				os.Remove(target)
			case "empty":
				os.WriteFile(target, nil, 0o600)
			case "oversized":
				os.WriteFile(target, make([]byte, maxDataFile+1), 0o600)
			}
			if _, err := Load(manifest); err == nil {
				t.Fatal("accepted unavailable or corrupted bound file")
			}
		})
	}
}

func TestInvalidSourceRecordsRejectedEvenWithRebuiltHashes(t *testing.T) {
	for _, mode := range []string{"duplicate-cve", "count", "local-provenance", "invalid-date", "duplicate-json-key", "invalid-license", "index-version", "index-count", "index-path", "index-severity", "index-score", "index-id-mismatch", "index-protocol", "index-path-protocol", "index-duplicate-path", "index-title-control", "index-unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			manifest := fixture(t)
			root := filepath.Dir(manifest)
			path := filepath.Join(root, "vulnerability-intel.json")
			raw, _ := os.ReadFile(path)
			var c kevCatalog
			json.Unmarshal(raw, &c)
			switch mode {
			case "duplicate-cve":
				c.Vulnerabilities[1].CVEID = c.Vulnerabilities[0].CVEID
			case "count":
				c.Count++
			case "local-provenance":
				c.Source.Kind = "local-unverified"
			case "invalid-date":
				c.Vulnerabilities[0].DueDate = "2026-02-30"
			case "invalid-license":
				c.LicenseURL = "https://unrelated.invalid/LICENSE"
			}
			writeJSON(t, path, c)
			if mode == "duplicate-json-key" {
				b, _ := os.ReadFile(path)
				os.WriteFile(path, []byte(strings.Replace(string(b), `"schema_version": 1,`, `"schema_version": 1,"schema_version": 1,`, 1)), 0o600)
			}
			if strings.HasPrefix(mode, "index-") {
				indexPath := filepath.Join(root, "nuclei-cve-index.json")
				b, _ := os.ReadFile(indexPath)
				var x templateIndex
				json.Unmarshal(b, &x)
				switch mode {
				case "index-version":
					x.Source.Release = "v9.9.9"
				case "index-count":
					x.Count++
				case "index-path":
					x.Templates[0].Path = "../evil.yaml"
				case "index-severity":
					x.Templates[0].Severity = "verified"
				case "index-score":
					score := 99.
					x.Templates[0].CVSSScore = &score
				case "index-id-mismatch":
					x.Templates[0].TemplateID = "CVE-2026-99999-other"
				case "index-protocol":
					x.Templates[0].Protocol = "ftp"
				case "index-path-protocol":
					x.Templates[0].Path = "network/cves/2026/gateway.yaml"
				case "index-duplicate-path":
					x.Templates[1].Path = x.Templates[0].Path
				case "index-title-control":
					x.Templates[0].Title = "metadata\nrequest"
				}
				writeJSON(t, indexPath, x)
				if mode == "index-unknown-field" {
					b, _ := os.ReadFile(indexPath)
					var rawIndex map[string]any
					json.Unmarshal(b, &rawIndex)
					rawIndex["templates"].([]any)[0].(map[string]any)["payload"] = "metadata must not contain executable request fields"
					writeJSON(t, indexPath, rawIndex)
				}
			}
			bind(t, root)
			if _, err := Load(manifest); err == nil {
				t.Fatal("accepted malformed data with valid local hash")
			}
		})
	}
}

func TestManifestAndPathBoundaries(t *testing.T) {
	for _, mode := range []string{"traversal", "duplicate-entry", "unknown-field", "bad-sha", "bad-date", "scope-claim", "symlink-escape", "license-symlink"} {
		t.Run(mode, func(t *testing.T) {
			manifest := fixture(t)
			root := filepath.Dir(manifest)
			raw, _ := os.ReadFile(manifest)
			var m Manifest
			json.Unmarshal(raw, &m)
			switch mode {
			case "traversal":
				m.Files[0].Path = "../vulnerability-intel.json"
			case "duplicate-entry":
				m.Files[1] = m.Files[0]
			case "bad-sha":
				m.Files[0].SHA256 = "garbage"
			case "bad-date":
				m.Files[0].SourceDate = "2026-99-99"
			case "scope-claim":
				m.Scope = "complete vulnerability proof"
			}
			writeJSON(t, manifest, m)
			if mode == "unknown-field" {
				b, _ := os.ReadFile(manifest)
				os.WriteFile(manifest, []byte(strings.Replace(string(b), `"schema_version": 1,`, `"unknown": true,"schema_version": 1,`, 1)), 0o600)
			}
			if mode == "symlink-escape" || mode == "license-symlink" {
				name := "vulnerability-intel.json"
				if mode == "license-symlink" {
					name = "discovery/NUCLEI-LICENSE.txt"
				}
				path := filepath.Join(root, name)
				b, _ := os.ReadFile(path)
				outside := filepath.Join(t.TempDir(), "outside")
				os.WriteFile(outside, b, 0o600)
				os.Remove(path)
				if err := os.Symlink(outside, path); err != nil {
					t.Skip("symlinks unavailable")
				}
			}
			if _, err := Load(manifest); err == nil {
				t.Fatal("accepted invalid manifest or escaped path")
			}
		})
	}
}

func TestRealRepositoryPack(t *testing.T) {
	// This is an offline integration check against the shipped snapshot files.
	manifest := filepath.Join("..", "packaging", "discovery-data-manifest.json")
	p, err := Load(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if p.kev.Count < 1 || len(p.tools) != 6 || p.index.Count < 1 {
		t.Fatal("shipped data missing")
	}
	result, err := p.Search(Query{Vendor: "Microsoft", Limit: 3})
	if err != nil || result.Total < 1 || result.Returned > 3 {
		t.Fatalf("real query failed: %+v / %v", result, err)
	}
}
