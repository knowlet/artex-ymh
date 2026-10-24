package skillprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// EvidenceState distinguishes absent evidence from a verified negative result.
// Offline inspection never asserts agent visibility or tool runtime readiness.
type EvidenceState string

const (
	Unknown  EvidenceState = "unknown"
	Verified EvidenceState = "verified"
	Missing  EvidenceState = "missing"
	Mismatch EvidenceState = "mismatch"
)

type ToolReadiness struct {
	ID                 string        `json:"id"`
	Aliases            []string      `json:"aliases"`
	Metadata           bool          `json:"metadata"`
	Registered         EvidenceState `json:"registered"`
	BinaryHashVerified EvidenceState `json:"binary_hash_verified"`
	RuntimeVerified    EvidenceState `json:"runtime_verified"`
}

type SkillReadiness struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Metadata     bool            `json:"metadata"`
	Provenance   string          `json:"provenance"`
	ImportPolicy string          `json:"import_policy"`
	Imported     EvidenceState   `json:"imported"`
	AgentVisible EvidenceState   `json:"agent_visible"`
	Dependencies []ToolReadiness `json:"dependencies"`
}

type ReadinessReport struct {
	Provider      string           `json:"provider"`
	Revision      string           `json:"revision"`
	CatalogSHA256 string           `json:"catalog_sha256"`
	Skills        []SkillReadiness `json:"skills"`
}

// ResolveDependency resolves an explicit catalog ID or alias, never arbitrary
// mentions in instructions. Resolution is metadata, not a registration check.
func (c *Catalog) ResolveDependency(alias string) (Dependency, bool) {
	want := strings.ToLower(alias)
	// Match Catalog.Validate: EqualFold would merge distinct Unicode aliases.
	for _, d := range c.Dependencies {
		if strings.ToLower(d.ID) == want { //nolint:staticcheck // SA6005: intentional Unicode comparison
			return d, true
		}
		for _, a := range d.Aliases {
			if strings.ToLower(a) == want { //nolint:staticcheck // SA6005: intentional Unicode comparison
				return d, true
			}
		}
	}
	return Dependency{}, false
}

// Inspect verifies only files covered by an import receipt in a local library.
// The catalog/receipt are identity records, not signatures or authorization.
// Missing receipt data cannot prove import. Tampered data fails closed.
// Agent visibility, registration, binary hashes and runtime execution need
// separate deployment evidence and remain unknown here.
func Inspect(c *Catalog, library string) (*ReadinessReport, error) {
	catalogHash, err := CatalogDigest(c)
	if err != nil {
		return nil, err
	}
	report := &ReadinessReport{Provider: c.Provider, Revision: c.Source.Revision, CatalogSHA256: catalogHash, Skills: []SkillReadiness{}}
	for _, e := range c.Skills {
		status := SkillReadiness{ID: e.ID, Name: SkillName(c, e), Metadata: true, Provenance: e.Provenance, ImportPolicy: e.ImportPolicy, Imported: Missing, AgentVisible: Unknown, Dependencies: []ToolReadiness{}}
		for _, id := range e.Dependencies {
			d, _ := c.ResolveDependency(id)
			status.Dependencies = append(status.Dependencies, ToolReadiness{ID: d.ID, Aliases: d.Aliases, Metadata: true, Registered: Unknown, BinaryHashVerified: Unknown, RuntimeVerified: Unknown})
		}
		report.Skills = append(report.Skills, status)
	}
	if library == "" {
		return report, nil
	}
	root, err := openDirectory(library)
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	raw, err := root.readFile(ReceiptFilename, MaxCatalogBytes)
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err != nil {
		return nil, err
	}
	receipt, err := parseReceipt(raw)
	if err != nil {
		return nil, err
	}
	if err := validateLibraryMarker(root, receipt.LibraryID); err != nil {
		return nil, err
	}
	if receipt.SchemaVersion != SchemaVersion || receipt.Provider != c.Provider || receipt.Namespace != c.Namespace || receipt.Revision != c.Source.Revision || receipt.CatalogSHA256 != catalogHash || len(receipt.Skills) == 0 || len(receipt.Skills) > MaxSkills {
		return nil, fmt.Errorf("import receipt does not match catalog")
	}
	indexes := map[string]int{}
	for i, e := range c.Skills {
		indexes[e.ID] = i
	}
	seen := map[string]bool{}
	for _, imported := range receipt.Skills {
		i, ok := indexes[imported.ID]
		if !ok || seen[imported.ID] {
			return nil, fmt.Errorf("unknown or duplicate receipt skill")
		}
		seen[imported.ID] = true
		e := c.Skills[i]
		if imported.Name != SkillName(c, e) || imported.SourceSHA256 != e.SourceSHA256 || imported.LicenseSHA256 != c.Source.License.SHA256 || !digest.MatchString(imported.SkillSHA256) {
			return nil, fmt.Errorf("invalid receipt hashes or name")
		}
		status := Verified
		if e.Provenance != "verified" || e.ImportPolicy != "allowed" {
			status = Mismatch
		}
		// Regenerate from catalog-pinned source. A locally editable receipt
		// alone must not certify an edited active instruction file.
		var original []byte
		for _, file := range []struct {
			path, want string
			limit      int64
		}{
			{imported.Name + "/references/source.md", imported.SourceSHA256, MaxSourceBytes},
			{imported.Name + "/references/LICENSE", imported.LicenseSHA256, maxLicenseBytes},
			{imported.Name + "/SKILL.md", imported.SkillSHA256, MaxSourceBytes},
		} {
			data, err := root.readFile(file.path, file.limit)
			if errors.Is(err, os.ErrNotExist) {
				if status != Mismatch {
					status = Missing
				}
				continue
			}
			if err != nil {
				return nil, err
			}
			if hashBytes(data) != file.want {
				status = Mismatch
			}
			if strings.HasSuffix(file.path, "/references/source.md") {
				original = data
			}
		}
		if original != nil {
			converted, err := convert(c, e, original)
			if err != nil || int64(len(original)) != e.SourceBytes || hashBytes(converted) != imported.SkillSHA256 {
				status = Mismatch
			}
		}
		report.Skills[i].Imported = status
	}
	return report, nil
}

var libraryIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func parseReceipt(raw []byte) (*Receipt, error) {
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, fmt.Errorf("import receipt: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("import receipt must contain one JSON object")
	}
	if receipt.SchemaVersion != SchemaVersion || !libraryIDPattern.MatchString(receipt.LibraryID) || receipt.LibraryID == strings.Repeat("0", 32) {
		return nil, fmt.Errorf("import receipt has invalid or missing library identity; reimport into a new library")
	}
	return &receipt, nil
}

// LibraryIdentity returns the persistent identity of an imported library.
// No provider records denotes a legacy skill directory. Existing malformed or old
// receipts, or a missing receipt with a retained marker, fail closed. A copy
// of an intact library retains its identity; each new Import creates a fresh one.
func LibraryIdentity(library string) (string, error) {
	if _, err := os.Lstat(filepath.Join(library, ReceiptFilename)); errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Lstat(filepath.Join(library, LibraryIDFilename)); errors.Is(markerErr, os.ErrNotExist) {
			return "", nil
		} else if markerErr != nil {
			return "", markerErr
		}
		return "", fmt.Errorf("provider library receipt missing")
	} else if err != nil {
		return "", err
	}
	root, err := openDirectory(library)
	if err != nil {
		return "", err
	}
	defer root.Close()
	raw, err := root.readFile(ReceiptFilename, MaxCatalogBytes)
	if err != nil {
		return "", err
	}
	receipt, err := parseReceipt(raw)
	if err != nil {
		return "", err
	}
	if err := validateLibraryMarker(root, receipt.LibraryID); err != nil {
		return "", err
	}
	return receipt.LibraryID, nil
}

func validateLibraryMarker(root *safeDir, libraryID string) error {
	marker, err := root.readFile(LibraryIDFilename, 33)
	if err != nil || string(marker) != libraryID+"\n" {
		return fmt.Errorf("provider library identity marker missing or mismatched")
	}
	return nil
}
