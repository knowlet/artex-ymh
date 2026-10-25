// Package intelpack reads an offline, hash-bound discovery intelligence pack.
// Source metadata and matching CVE IDs are not evidence about a tested target.
package intelpack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultLimit = 20
	MaxLimit     = 100
	maxManifest  = 64 << 10
	maxDataFile  = 8 << 20
	packKind     = "artex-discovery-intelligence"
	packScope    = "CISA KEV and ProjectDiscovery release metadata; not complete CVE List or target evidence."
)

var (
	cvePattern          = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	cwePattern          = regexp.MustCompile(`^CWE-[0-9]+$`)
	commitPattern       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionPattern      = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	templateIDPattern   = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,19})(?:-[A-Za-z0-9_-]+)?$`)
	templatePathPattern = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
	yearPattern         = regexp.MustCompile(`^[0-9]{4}$`)
)

// File describes the bytes stored beside the manifest. SHA256 is the local
// snapshot file hash, distinct from any upstream raw-source or archive hash.
type File struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	License    string `json:"license"`
	SourceDate string `json:"source_date"`
}

type Manifest struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Scope         string `json:"scope"`
	Files         []File `json:"files"`
}

type Source struct {
	Kind       string `json:"kind"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	SHA256     string `json:"sha256"`
	URL        string `json:"url"`
}

type Vulnerability struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DateAdded                  string   `json:"dateAdded"`
	DueDate                    string   `json:"dueDate"`
	Notes                      string   `json:"notes,omitempty"`
	CWEs                       []string `json:"cwes,omitempty"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse,omitempty"`
}

type kevCatalog struct {
	SchemaVersion   int             `json:"schema_version"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	License         string          `json:"license"`
	LicenseURL      string          `json:"license_url"`
	Scope           string          `json:"scope"`
	Source          Source          `json:"source"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Tool struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	ReleasedAt string `json:"release_published_at"`
}

type releaseTool struct {
	Tool
	Repository string `json:"repository"`
	License    string `json:"license"`
	ReleaseURL string `json:"release_url"`
	SourceURL  string `json:"source_url"`
	Assets     []struct {
		Name   string `json:"name"`
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	} `json:"assets"`
}

type releaseLock struct {
	SchemaVersion int           `json:"schema_version"`
	Tools         []releaseTool `json:"tools"`
}

// Template is metadata about a published template, never an installed rule.
type Template struct {
	CVEID      string   `json:"cve_id"`
	TemplateID string   `json:"template_id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	CVSSScore  *float64 `json:"cvss_score,omitempty"`
	Path       string   `json:"path"`
	Protocol   string   `json:"protocol"`
}

type templateIndex struct {
	SchemaVersion  int    `json:"schema_version"`
	Scope          string `json:"scope"`
	License        string `json:"license"`
	LicenseFile    string `json:"license_file"`
	Count          int    `json:"count"`
	UniqueCVECount int    `json:"unique_cve_count"`
	Source         struct {
		Source
		BlobSHA     string `json:"blob_sha"`
		Release     string `json:"release"`
		PublishedAt string `json:"release_published_at"`
	} `json:"source"`
	Templates []Template `json:"templates"`
}

// Pack is immutable after Load. Every source is loaded and verified once.
type Pack struct {
	manifest Manifest
	kev      kevCatalog
	tools    []Tool
	index    templateIndex
}

type Status struct {
	Kind              string   `json:"kind"`
	Integrity         string   `json:"integrity"`
	Freshness         string   `json:"freshness"`
	Scope             string   `json:"scope"`
	KEVCount          int      `json:"kev_count"`
	CatalogVersion    string   `json:"catalog_version"`
	PublishedAt       string   `json:"published_at"`
	AgeSeconds        int64    `json:"age_seconds"`
	TimestampInFuture bool     `json:"timestamp_in_future"`
	KEVSource         Source   `json:"kev_source"`
	Tools             []Tool   `json:"desired_tool_releases"`
	TemplateCount     int      `json:"template_metadata_count"`
	TemplateCVECount  int      `json:"template_cve_count"`
	Caveats           []string `json:"caveats"`
}

var caveats = []string{
	"Offline hashes verify the bytes bound by this local manifest; they do not independently authenticate upstream sources or prove current freshness.",
	"KEV is a subset of known CVEs. Absence from this snapshot is not evidence that a product is safe or a CVE is not exploited.",
	"Release and template records are metadata, not installation, scan coverage, or confirmed target vulnerabilities.",
}

func (p *Pack) Status(now time.Time) Status {
	published, _ := time.Parse(time.RFC3339Nano, p.kev.DateReleased)
	return Status{
		Kind: packKind, Integrity: "local-file-hashes-verified", Freshness: "not-checked-online", Scope: p.manifest.Scope,
		KEVCount: p.kev.Count, CatalogVersion: p.kev.CatalogVersion, PublishedAt: p.kev.DateReleased,
		AgeSeconds: int64(now.Sub(published).Seconds()), TimestampInFuture: now.Before(published),
		KEVSource: p.kev.Source, Tools: append([]Tool(nil), p.tools...),
		TemplateCount: p.index.Count, TemplateCVECount: p.index.UniqueCVECount,
		Caveats: append([]string(nil), caveats...),
	}
}

type Query struct {
	CVE     string
	Vendor  string
	Product string
	Text    string
	Limit   int
}

type SearchResult struct {
	CatalogVersion      string          `json:"catalog_version"`
	PublishedAt         string          `json:"published_at"`
	Source              Source          `json:"source"`
	TargetVulnerability string          `json:"target_vulnerability"`
	Total               int             `json:"total_kev_matches"`
	Returned            int             `json:"returned_kev_matches"`
	Truncated           bool            `json:"kev_truncated"`
	Limit               int             `json:"limit"`
	Matches             []Vulnerability `json:"kev_matches"`
	TemplateTotal       int             `json:"total_template_matches"`
	TemplateTruncated   bool            `json:"templates_truncated"`
	TemplateMatches     []Template      `json:"template_matches"`
	Caveats             []string        `json:"caveats"`
}

// Search uses AND semantics for KEV filters. --cve also finds metadata for that
// CVE even when it is absent from KEV. No finding is created or validated.
func (p *Pack) Search(q Query) (SearchResult, error) {
	for _, value := range []string{q.CVE, q.Vendor, q.Product, q.Text} {
		if len(value) > 1024 || strings.ContainsRune(value, '\x00') {
			return SearchResult{}, fmt.Errorf("query fields must be at most 1024 bytes without NUL")
		}
	}
	q.CVE = strings.ToUpper(strings.TrimSpace(q.CVE))
	q.Vendor = strings.ToLower(strings.TrimSpace(q.Vendor))
	q.Product = strings.ToLower(strings.TrimSpace(q.Product))
	q.Text = strings.ToLower(strings.TrimSpace(q.Text))
	if q.CVE != "" && !cvePattern.MatchString(q.CVE) {
		return SearchResult{}, fmt.Errorf("--cve requires one complete CVE ID")
	}
	if q.CVE == "" && q.Vendor == "" && q.Product == "" && q.Text == "" {
		return SearchResult{}, fmt.Errorf("at least one search filter is required")
	}
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	if q.Limit < 1 || q.Limit > MaxLimit {
		return SearchResult{}, fmt.Errorf("limit must be between 1 and %d", MaxLimit)
	}
	result := SearchResult{
		CatalogVersion: p.kev.CatalogVersion, PublishedAt: p.kev.DateReleased, Source: p.kev.Source,
		TargetVulnerability: "unverified", Limit: q.Limit, Matches: []Vulnerability{}, TemplateMatches: []Template{},
		Caveats: append([]string(nil), caveats...),
	}
	matchedIDs := map[string]bool{}
	for _, row := range p.kev.Vulnerabilities {
		if q.CVE != "" && row.CVEID != q.CVE || !containsFold(row.VendorProject, q.Vendor) || !containsFold(row.Product, q.Product) {
			continue
		}
		searchable := row.CVEID + " " + row.VendorProject + " " + row.Product + " " + row.VulnerabilityName + " " + row.ShortDescription
		if !containsFold(searchable, q.Text) {
			continue
		}
		result.Total++
		matchedIDs[row.CVEID] = true
		if len(result.Matches) < q.Limit {
			row.CWEs = append([]string(nil), row.CWEs...)
			result.Matches = append(result.Matches, row)
		}
	}
	for _, row := range p.index.Templates {
		// General vendor/product searches map metadata via matching KEV IDs.
		// Exact-CVE-only queries also expose index-only candidates distinctly.
		if !matchedIDs[row.CVEID] && !(q.CVE != "" && row.CVEID == q.CVE && q.Vendor == "" && q.Product == "" && q.Text == "") {
			continue
		}
		result.TemplateTotal++
		if len(result.TemplateMatches) < q.Limit {
			if row.CVSSScore != nil {
				score := *row.CVSSScore
				row.CVSSScore = &score
			}
			result.TemplateMatches = append(result.TemplateMatches, row)
		}
	}
	result.Returned = len(result.Matches)
	result.Truncated = result.Total > len(result.Matches)
	result.TemplateTruncated = result.TemplateTotal > len(result.TemplateMatches)
	return result, nil
}

func containsFold(haystack, lowercaseNeedle string) bool {
	return lowercaseNeedle == "" || strings.Contains(strings.ToLower(haystack), lowercaseNeedle)
}

// Load validates file containment, exact local sizes/hashes, record identities,
// source metadata, counts, dates, and duplicate JSON keys before exposing data.
func Load(manifestPath string) (*Pack, error) {
	abs, err := filepath.Abs(manifestPath)
	if err != nil {
		return nil, err
	}
	realManifest, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(realManifest)
	raw, err := readRegular(realManifest, maxManifest)
	if err != nil {
		return nil, fmt.Errorf("read data-pack manifest: %w", err)
	}
	var m Manifest
	if err = decode(raw, &m, true); err != nil {
		return nil, fmt.Errorf("invalid data-pack manifest: %w", err)
	}
	if m.SchemaVersion != 1 || m.Kind != packKind || m.Scope != packScope || len(m.Files) != 3 {
		return nil, fmt.Errorf("unsupported or incomplete data-pack manifest")
	}
	wanted := []struct{ name, path, license string }{
		{"cisa-kev", "vulnerability-intel.json", "CC0-1.0"},
		{"projectdiscovery-releases", "projectdiscovery-lock.json", "MIT"},
		{"nuclei-cve-index", "nuclei-cve-index.json", "MIT"},
	}
	files := make([][]byte, len(m.Files))
	for i, entry := range m.Files {
		if entry.Name != wanted[i].name || entry.Path != wanted[i].path || entry.License != wanted[i].license || entry.Bytes < 1 || entry.Bytes > maxDataFile || !hashPattern.MatchString(entry.SHA256) {
			return nil, fmt.Errorf("invalid data-pack file entry %d", i)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.SourceDate); err != nil {
			return nil, fmt.Errorf("invalid source date for %s", entry.Name)
		}
		path, err := containedPath(root, entry.Path)
		if err != nil {
			return nil, err
		}
		b, err := readRegular(path, maxDataFile)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name, err)
		}
		sum := sha256.Sum256(b)
		if int64(len(b)) != entry.Bytes || hex.EncodeToString(sum[:]) != entry.SHA256 {
			return nil, fmt.Errorf("data-pack size or SHA-256 mismatch: %s", entry.Name)
		}
		files[i] = b
	}
	p := &Pack{manifest: m}
	if err := decode(files[0], &p.kev, false); err != nil {
		return nil, fmt.Errorf("invalid KEV snapshot: %w", err)
	}
	if err := p.validateKEV(); err != nil {
		return nil, err
	}
	var lock releaseLock
	if err := decode(files[1], &lock, false); err != nil {
		return nil, fmt.Errorf("invalid release lock: %w", err)
	}
	if err := p.validateReleases(lock); err != nil {
		return nil, err
	}
	if err := decode(files[2], &p.index, true); err != nil {
		return nil, fmt.Errorf("invalid Nuclei CVE metadata index: %w", err)
	}
	if err := p.validateIndex(root); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Pack) validateKEV() error {
	c := &p.kev
	if c.SchemaVersion != 1 || c.Count < 1 || c.Count != len(c.Vulnerabilities) || c.License != "CC0-1.0" || strings.TrimSpace(c.CatalogVersion) == "" || c.Scope != "CISA KEV only; not the complete CVE List" {
		return fmt.Errorf("invalid KEV catalog identity or count")
	}
	if err := validateSource(c.Source, "cisagov/kev-data", "known_exploited_vulnerabilities.json"); err != nil {
		return err
	}
	if c.LicenseURL != "https://github.com/cisagov/kev-data/blob/"+c.Source.Commit+"/LICENSE" || c.DateReleased != p.manifest.Files[0].SourceDate {
		return fmt.Errorf("KEV license or source date does not match manifest")
	}
	released, err := time.Parse(time.RFC3339Nano, c.DateReleased)
	if err != nil {
		return fmt.Errorf("invalid KEV release date")
	}
	seen := map[string]bool{}
	for _, row := range c.Vulnerabilities {
		if !cvePattern.MatchString(row.CVEID) || seen[row.CVEID] {
			return fmt.Errorf("invalid or duplicate KEV CVE ID")
		}
		seen[row.CVEID] = true
		for _, value := range []string{row.VendorProject, row.Product, row.VulnerabilityName, row.ShortDescription, row.RequiredAction} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("missing KEV entry field: %s", row.CVEID)
			}
		}
		for _, cwe := range row.CWEs {
			if !cwePattern.MatchString(cwe) {
				return fmt.Errorf("invalid KEV CWE identifier")
			}
		}
		added, e1 := time.Parse("2006-01-02", row.DateAdded)
		due, e2 := time.Parse("2006-01-02", row.DueDate)
		if e1 != nil || e2 != nil || due.Before(added) || row.DateAdded > released.Format("2006-01-02") {
			return fmt.Errorf("invalid KEV entry dates: %s", row.CVEID)
		}
	}
	sort.Slice(c.Vulnerabilities, func(i, j int) bool { return c.Vulnerabilities[i].CVEID < c.Vulnerabilities[j].CVEID })
	return nil
}

func (p *Pack) validateReleases(lock releaseLock) error {
	names := []string{"nuclei", "httpx", "naabu", "katana", "subfinder", "nuclei-templates"}
	if lock.SchemaVersion != 1 || len(lock.Tools) != len(names) {
		return fmt.Errorf("invalid ProjectDiscovery release lock identity")
	}
	var latest time.Time
	for i, row := range lock.Tools {
		base := "https://github.com/projectdiscovery/" + names[i]
		if row.Name != names[i] || row.Repository != "projectdiscovery/"+names[i] || row.License != "MIT" || !versionPattern.MatchString(row.Version) || !commitPattern.MatchString(row.Commit) || row.ReleaseURL != base+"/releases/tag/"+row.Version || row.SourceURL != base+"/tree/"+row.Commit || len(row.Assets) < 1 {
			return fmt.Errorf("invalid ProjectDiscovery release metadata: %s", names[i])
		}
		published, err := time.Parse(time.RFC3339Nano, row.ReleasedAt)
		if err != nil {
			return fmt.Errorf("invalid ProjectDiscovery release date")
		}
		if published.After(latest) {
			latest = published
		}
		seen := map[string]bool{}
		for _, a := range row.Assets {
			if !safeRelative(a.Name) || strings.Contains(a.Name, "/") || seen[a.Name] || !hashPattern.MatchString(a.SHA256) || a.URL != base+"/releases/download/"+row.Version+"/"+a.Name {
				return fmt.Errorf("invalid ProjectDiscovery asset metadata")
			}
			seen[a.Name] = true
		}
		p.tools = append(p.tools, row.Tool)
	}
	manifestDate, _ := time.Parse(time.RFC3339Nano, p.manifest.Files[1].SourceDate)
	if !latest.Equal(manifestDate) {
		return fmt.Errorf("release lock date does not match manifest")
	}
	return nil
}

func (p *Pack) validateIndex(root string) error {
	x := &p.index
	if x.SchemaVersion != 1 || x.License != "MIT" || x.LicenseFile != "discovery/NUCLEI-LICENSE.txt" || x.Count < 1 || x.Count != len(x.Templates) || !commitPattern.MatchString(x.Source.BlobSHA) || !versionPattern.MatchString(x.Source.Release) || x.Source.PublishedAt != p.manifest.Files[2].SourceDate {
		return fmt.Errorf("invalid Nuclei CVE index identity, count, or date")
	}
	if err := validateSource(x.Source.Source, "projectdiscovery/nuclei-templates", "cves.json"); err != nil {
		return err
	}
	for _, tool := range p.tools {
		if tool.Name == "nuclei-templates" && (tool.Version != x.Source.Release || tool.Commit != x.Source.Commit || tool.ReleasedAt != x.Source.PublishedAt) {
			return fmt.Errorf("Nuclei CVE index does not match the pinned templates release")
		}
	}
	license, err := containedPath(root, x.LicenseFile)
	if err != nil {
		return err
	}
	licenseBytes, err := readRegular(license, 128<<10)
	if err != nil || !bytes.HasPrefix(licenseBytes, []byte("MIT License")) || !bytes.Contains(licenseBytes, []byte("Permission is hereby granted, free of charge")) || !bytes.Contains(licenseBytes, []byte("The above copyright notice and this permission notice shall be included")) || !bytes.Contains(licenseBytes, []byte(`THE SOFTWARE IS PROVIDED "AS IS"`)) {
		return fmt.Errorf("Nuclei index MIT notice is missing or invalid")
	}
	cves, rows := map[string]bool{}, map[string]bool{}
	for _, row := range x.Templates {
		identity := templateIDPattern.FindStringSubmatch(row.TemplateID)
		parts := strings.Split(row.Path, "/")
		validProtocol := row.Protocol == "http" || row.Protocol == "network" || row.Protocol == "javascript"
		validPath := safeRelative(row.Path) && len(row.Path) <= 512 && templatePathPattern.MatchString(row.Path) && len(parts) >= 4 && parts[0] == row.Protocol && parts[1] == "cves" && yearPattern.MatchString(parts[2]) && (strings.HasSuffix(row.Path, ".yaml") || strings.HasSuffix(row.Path, ".yml"))
		if !cvePattern.MatchString(row.CVEID) || len(identity) != 2 || identity[1] != row.CVEID || len(row.TemplateID) > 160 || !validMetadataText(row.Title, 2048) || !validProtocol || !validPath || rows[row.Path] || row.CVSSScore != nil && (*row.CVSSScore < 0 || *row.CVSSScore > 10) {
			return fmt.Errorf("invalid or duplicate Nuclei CVE index entry")
		}
		switch row.Severity {
		case "unknown", "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid Nuclei metadata severity")
		}
		rows[row.Path], cves[row.CVEID] = true, true
	}
	if x.UniqueCVECount != len(cves) {
		return fmt.Errorf("Nuclei unique CVE count does not match entries")
	}
	sort.Slice(x.Templates, func(i, j int) bool {
		a, b := x.Templates[i], x.Templates[j]
		return a.CVEID+"\x00"+a.TemplateID+"\x00"+a.Path < b.CVEID+"\x00"+b.TemplateID+"\x00"+b.Path
	})
	return nil
}

func validMetadataText(s string, maxRunes int) bool {
	if strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	for _, r := range s {
		if r < 32 {
			return false
		}
	}
	return true
}

func validateSource(s Source, repo, file string) error {
	if s.Kind != "official-github" || s.Repository != repo || !commitPattern.MatchString(s.Commit) || !hashPattern.MatchString(s.SHA256) || s.URL != "https://raw.githubusercontent.com/"+repo+"/"+s.Commit+"/"+file {
		return fmt.Errorf("invalid official-source metadata for %s", repo)
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.Host != "raw.githubusercontent.com" {
		return fmt.Errorf("invalid source URL")
	}
	return nil
}

func safeRelative(path string) bool {
	return path != "" && path != "." && !filepath.IsAbs(path) && filepath.ToSlash(filepath.Clean(path)) == path && path != ".." && !strings.HasPrefix(path, "../") && !strings.ContainsAny(path, "\\\x00\r\n")
}

func containedPath(root, relative string) (string, error) {
	if !safeRelative(relative) {
		return "", fmt.Errorf("unsafe data-pack relative path")
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("data-pack file escapes manifest directory")
	}
	return real, nil
}

func readRegular(path string, max int64) ([]byte, error) {
	// Check type before opening: opening a named pipe may block indefinitely.
	// The post-open check below still verifies the descriptor actually opened.
	// As with the other local pack files, hostile concurrent path replacement
	// is outside this reader's filesystem trust boundary.
	before, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > max {
		return nil, fmt.Errorf("data-pack file must be nonempty, regular, and at most %d bytes", max)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max {
		return nil, fmt.Errorf("data-pack file must be nonempty, regular, and at most %d bytes", max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || len(b) == 0 || int64(len(b)) > max {
		return nil, fmt.Errorf("data-pack read failed or exceeds size bound")
	}
	return b, nil
}

func decode(raw []byte, value any, strict bool) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON must be valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := checkUnique(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("JSON contains trailing data")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	if strict {
		d.DisallowUnknownFields()
	}
	return d.Decode(value)
}

func checkUnique(d *json.Decoder, depth int) error {
	if depth > 128 {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate or invalid JSON object key")
			}
			seen[key] = true
			if err := checkUnique(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkUnique(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}
