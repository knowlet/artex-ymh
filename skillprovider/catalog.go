// Package skillprovider handles reviewed instruction metadata and offline imports.
// It does not install, register, or execute tools, and never grants agent visibility.
package skillprovider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	SchemaVersion     = 1
	MaxCatalogBytes   = 2 << 20
	MaxSourceBytes    = 1 << 20
	MaxTotalBytes     = 32 << 20
	MaxSkills         = 100
	ReceiptFilename   = ".provider-import.json"
	LibraryIDFilename = ".provider-library-id"
)

type Catalog struct {
	SchemaVersion int          `json:"schema_version"`
	Provider      string       `json:"provider"`
	Namespace     string       `json:"namespace"`
	Source        Source       `json:"source"`
	Skills        []Entry      `json:"skills"`
	Dependencies  []Dependency `json:"dependencies"`
}

type Source struct {
	Repository string  `json:"repository"`
	Revision   string  `json:"revision"`
	License    License `json:"license"`
}

type License struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	SPDX   string `json:"spdx"`
}

type Entry struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"`
	SourcePath   string   `json:"source_path"`
	SourceSHA256 string   `json:"source_sha256"`
	SourceBytes  int64    `json:"source_bytes"`
	Description  string   `json:"description"`
	Format       string   `json:"format"`
	Provenance   string   `json:"provenance"`
	ImportPolicy string   `json:"import_policy"`
	Dependencies []string `json:"dependencies"`
}

type Dependency struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type Receipt struct {
	LibraryID     string          `json:"library_id"`
	SchemaVersion int             `json:"schema_version"`
	Provider      string          `json:"provider"`
	Namespace     string          `json:"namespace"`
	Revision      string          `json:"revision"`
	CatalogSHA256 string          `json:"catalog_sha256"`
	Skills        []ImportedSkill `json:"skills"`
}

type ImportedSkill struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	SourceSHA256  string `json:"source_sha256"`
	SkillSHA256   string `json:"skill_sha256"`
	LicenseSHA256 string `json:"license_sha256"`
}

var slug = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadCatalogFile opens a bounded regular local catalog without following any
// symlink components. This prevents a FIFO/device from blocking the CLI before
// ParseCatalog can enforce its input limit.
func LoadCatalogFile(filename string) (*Catalog, error) {
	parentPath, name, err := destinationParts(filename)
	if err != nil {
		return nil, fmt.Errorf("catalog path: %w", err)
	}
	parent, err := openDirectory(parentPath)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	data, err := parent.readFile(name, MaxCatalogBytes)
	if err != nil {
		return nil, err
	}
	return ParseCatalog(bytes.NewReader(data))
}

// ParseCatalog bounds input and rejects unknown fields and duplicate JSON keys.
func ParseCatalog(r io.Reader) (*Catalog, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxCatalogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxCatalogBytes || !utf8.Valid(b) {
		return nil, fmt.Errorf("catalog exceeds limit or is not UTF-8")
	}
	if err := rejectDuplicateKeys(b); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func rejectDuplicateKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("JSON nesting exceeds limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return fmt.Errorf("duplicate or invalid JSON key %v", k)
				}
				// encoding/json otherwise accepts case variants of tagged fields,
				// which could shadow a second spelling of the same schema key.
				if s != strings.ToLower(s) {
					return fmt.Errorf("JSON field names must use exact lowercase schema spelling: %q", s)
				}
				seen[s] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("catalog must contain exactly one JSON value")
	}
	return nil
}

func validSlug(s string) bool { return len(s) <= 64 && slug.MatchString(s) }
func validText(s string, limit int) bool {
	return len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) != "" && !strings.ContainsRune(s, '\x00')
}
func validSourcePath(s string) bool {
	return len(s) <= 240 && fs.ValidPath(s) && s != "." && path.Clean(s) == s && !strings.ContainsAny(s, "\\:\x00") && utf8.ValidString(s)
}

func SkillName(c *Catalog, e Entry) string { return c.Namespace + "-" + e.ID }

func (c *Catalog) Validate() error {
	if c == nil || c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported catalog schema version")
	}
	if !validSlug(c.Provider) || !validSlug(c.Namespace) {
		return fmt.Errorf("invalid provider or namespace")
	}
	u, err := url.Parse(c.Source.Repository)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("repository must be an HTTPS source URL")
	}
	if !revision.MatchString(c.Source.Revision) {
		return fmt.Errorf("source revision must be a pinned 40-character SHA")
	}
	if !validSourcePath(c.Source.License.Path) || !digest.MatchString(c.Source.License.SHA256) || !validText(c.Source.License.SPDX, 128) {
		return fmt.Errorf("invalid pinned source license")
	}
	if len(c.Skills) == 0 || len(c.Skills) > MaxSkills || len(c.Dependencies) > 1000 {
		return fmt.Errorf("catalog entry count exceeds limits or is empty")
	}
	depIDs, aliases := map[string]bool{}, map[string]string{}
	for _, d := range c.Dependencies {
		if !validSlug(d.ID) || depIDs[d.ID] || len(d.Aliases) > 100 {
			return fmt.Errorf("invalid or duplicate dependency %q", d.ID)
		}
		depIDs[d.ID] = true
		for _, a := range append([]string{d.ID}, d.Aliases...) {
			if !validText(a, 128) || strings.TrimSpace(a) != a {
				return fmt.Errorf("invalid dependency alias")
			}
			key := strings.ToLower(a)
			if _, ok := aliases[key]; ok {
				return fmt.Errorf("duplicate dependency alias %q", a)
			}
			aliases[key] = d.ID
		}
	}
	ids, paths, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var total int64
	for _, e := range c.Skills {
		name := SkillName(c, e)
		if !validSlug(e.ID) || !validSlug(name) || ids[e.ID] || names[name] {
			return fmt.Errorf("invalid or duplicate skill name %q", name)
		}
		ids[e.ID], names[name] = true, true
		if !validSourcePath(e.SourcePath) || paths[e.SourcePath] || e.SourcePath == c.Source.License.Path {
			return fmt.Errorf("invalid or duplicate source path %q", e.SourcePath)
		}
		paths[e.SourcePath] = true
		if !digest.MatchString(e.SourceSHA256) || e.SourceBytes <= 0 || e.SourceBytes > MaxSourceBytes {
			return fmt.Errorf("invalid source hash or size for %s", e.ID)
		}
		total += e.SourceBytes
		if total > MaxTotalBytes {
			return fmt.Errorf("catalog source bytes exceed total limit")
		}
		if !validText(e.Category, 128) || !validText(e.Description, 4096) {
			return fmt.Errorf("empty or invalid category/description for %s", e.ID)
		}
		if e.Format != "frontmatter" && e.Format != "legacy" {
			return fmt.Errorf("unsupported skill format %q", e.Format)
		}
		if e.Provenance != "verified" && e.Provenance != "provenance-unverified" {
			return fmt.Errorf("unsupported provenance state")
		}
		if e.ImportPolicy != "allowed" && e.ImportPolicy != "metadata-only" {
			return fmt.Errorf("unsupported import policy")
		}
		if e.ImportPolicy == "allowed" && e.Provenance != "verified" {
			return fmt.Errorf("unverified provenance cannot be importable")
		}
		seen := map[string]bool{}
		for _, id := range e.Dependencies {
			if !depIDs[id] || seen[id] {
				return fmt.Errorf("unknown or duplicate dependency %q", id)
			}
			seen[id] = true
		}
	}
	return nil
}

func hashBytes(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }

// CatalogDigest hashes the validated canonical JSON representation, independent
// of whitespace in the manifest file. A digest proves identity, not provenance.
func CatalogDigest(c *Catalog) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return hashBytes(b), nil
}
