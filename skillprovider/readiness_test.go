package skillprovider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertOfflineEvidence(t *testing.T, report *ReadinessReport) {
	t.Helper()
	for _, skill := range report.Skills {
		if !skill.Metadata || skill.AgentVisible != Unknown {
			t.Fatalf("metadata inferred agent visibility: %+v", skill)
		}
		for _, dependency := range skill.Dependencies {
			if !dependency.Metadata || dependency.Registered != Unknown ||
				dependency.BinaryHashVerified != Unknown || dependency.RuntimeVerified != Unknown {
				t.Fatalf("metadata inferred executable readiness: %+v", dependency)
			}
		}
	}
}

func TestProviderInspectMissingEvidence(t *testing.T) {
	_, _, library := importerFixture(t)
	if _, err := Inspect(nil, library); err == nil {
		t.Fatal("missing catalog accepted")
	}
	for _, mode := range []string{"no library", "missing library", "missing receipt", "unreceipted skill"} {
		t.Run(mode, func(t *testing.T) {
			if mode != "no library" {
				requireLinuxFS(t)
			}
			c, _, library := importerFixture(t)
			switch mode {
			case "no library":
				library = ""
			case "missing receipt":
				if err := os.Mkdir(library, 0o700); err != nil {
					t.Fatal(err)
				}
			case "unreceipted skill":
				writeImporterFile(t, filepath.Join(library, "fixture-normal", "SKILL.md"), []byte(syntheticNormal))
			}
			report, err := Inspect(c, library)
			if err != nil {
				t.Fatal(err)
			}
			assertOfflineEvidence(t, report)
			for _, status := range report.Skills {
				if status.Imported != Missing {
					t.Fatalf("unreceipted content inferred import: %+v", status)
				}
			}
		})
	}
}

func TestProviderInspectImportedFilesAndDependencyEvidence(t *testing.T) {
	requireLinuxFS(t)
	c, source, library := importerFixture(t)
	if err := Import(context.Background(), c, source, library, []string{"normal"}); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(c, library)
	if err != nil {
		t.Fatal(err)
	}
	assertOfflineEvidence(t, report)
	if report.Skills[0].Imported != Verified || report.Skills[1].Imported != Missing {
		t.Fatalf("selected/unselected import states: %+v", report.Skills)
	}
	if report.Provider != c.Provider || report.Revision != c.Source.Revision || len(report.CatalogSHA256) != 64 {
		t.Fatalf("readiness lacks catalog identity: %+v", report)
	}
}

func TestProviderInspectAlteredAndMissingFiles(t *testing.T) {
	requireLinuxFS(t)
	for _, relative := range []string{"SKILL.md", "references/source.md", "references/LICENSE"} {
		for _, mode := range []string{"altered", "missing"} {
			t.Run(relative+"/"+mode, func(t *testing.T) {
				c, source, library := importerFixture(t)
				if err := Import(context.Background(), c, source, library, []string{"normal"}); err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(library, "fixture-normal", filepath.FromSlash(relative))
				want := Mismatch
				if mode == "missing" {
					want = Missing
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				} else {
					writeImporterFile(t, name, []byte("changed synthetic text\n"))
				}
				report, err := Inspect(c, library)
				if err != nil {
					t.Fatal(err)
				}
				assertOfflineEvidence(t, report)
				if report.Skills[0].Imported != want {
					t.Fatalf("import state=%s, want %s", report.Skills[0].Imported, want)
				}
			})
		}
	}
	t.Run("mismatch dominates missing evidence", func(t *testing.T) {
		c, source, library := importerFixture(t)
		if err := Import(context.Background(), c, source, library, []string{"normal"}); err != nil {
			t.Fatal(err)
		}
		writeImporterFile(t, filepath.Join(library, "fixture-normal", "SKILL.md"), []byte("altered\n"))
		if err := os.Remove(filepath.Join(library, "fixture-normal", "references", "source.md")); err != nil {
			t.Fatal(err)
		}
		// Repetition exposes map-order-dependent evidence downgrades.
		for range 25 {
			report, err := Inspect(c, library)
			if err != nil {
				t.Fatal(err)
			}
			if report.Skills[0].Imported != Mismatch {
				t.Fatalf("known mismatch lost to missing evidence: %+v", report.Skills[0])
			}
		}
	})
}

func TestProviderInspectRejectsMismatchedReceipts(t *testing.T) {
	requireLinuxFS(t)
	mutations := map[string]func(*Receipt){
		"unknown schema": func(r *Receipt) { r.SchemaVersion++ },
		"provider":       func(r *Receipt) { r.Provider = "different" },
		"namespace":      func(r *Receipt) { r.Namespace = "different" },
		"revision":       func(r *Receipt) { r.Revision = strings.Repeat("b", 40) },
		"catalog hash":   func(r *Receipt) { r.CatalogSHA256 = strings.Repeat("0", 64) },
		"empty skills":   func(r *Receipt) { r.Skills = nil },
		"unknown skill":  func(r *Receipt) { r.Skills[0].ID = "absent" },
		"duplicate skill": func(r *Receipt) {
			r.Skills = append(r.Skills, r.Skills[0])
		},
		"directory name": func(r *Receipt) { r.Skills[0].Name = "fixture-other" },
		"source hash":    func(r *Receipt) { r.Skills[0].SourceSHA256 = strings.Repeat("0", 64) },
		"license hash":   func(r *Receipt) { r.Skills[0].LicenseSHA256 = strings.Repeat("0", 64) },
		"invalid generated hash": func(r *Receipt) {
			r.Skills[0].SkillSHA256 = "unpinned"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c, source, library := importerFixture(t)
			if err := Import(context.Background(), c, source, library, []string{"normal"}); err != nil {
				t.Fatal(err)
			}
			receiptPath := filepath.Join(library, ReceiptFilename)
			var receipt Receipt
			if err := json.Unmarshal(readImporterFile(t, receiptPath), &receipt); err != nil {
				t.Fatal(err)
			}
			mutate(&receipt)
			bad, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			writeImporterFile(t, receiptPath, bad)
			if _, err := Inspect(c, library); err == nil {
				t.Fatal("accepted mismatched receipt")
			}
		})
	}
	for _, bad := range []string{"null", "{} {}", `{"schema_version":1,"schema_version":2}`, `{"unrecognized":true}`} {
		t.Run(bad, func(t *testing.T) {
			c, source, library := importerFixture(t)
			if err := Import(context.Background(), c, source, library, []string{"normal"}); err != nil {
				t.Fatal(err)
			}
			writeImporterFile(t, filepath.Join(library, ReceiptFilename), []byte(bad))
			if _, err := Inspect(c, library); err == nil {
				t.Fatal("accepted malformed receipt")
			}
		})
	}
	t.Run("catalog changed after import", func(t *testing.T) {
		c, source, library := importerFixture(t)
		if err := Import(context.Background(), c, source, library, []string{"normal"}); err != nil {
			t.Fatal(err)
		}
		c.Skills[0].Description = "A different reviewed catalog."
		if _, err := Inspect(c, library); err == nil {
			t.Fatal("accepted receipt for different catalog")
		}
	})
}

func TestProviderInspectDoesNotTrustRewrittenReceipt(t *testing.T) {
	requireLinuxFS(t)
	for _, mode := range []string{"forged generated hash", "unverified import claim"} {
		t.Run(mode, func(t *testing.T) {
			c, source, library := importerFixture(t)
			if err := Import(context.Background(), c, source, library, []string{"normal"}); err != nil {
				t.Fatal(err)
			}
			receiptPath := filepath.Join(library, ReceiptFilename)
			var receipt Receipt
			if err := json.Unmarshal(readImporterFile(t, receiptPath), &receipt); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "forged generated hash":
				altered := []byte("---\nname: fixture-normal\ndescription: Altered instructions.\n---\nChanged synthetic guidance.\n")
				writeImporterFile(t, filepath.Join(library, "fixture-normal", "SKILL.md"), altered)
				// A mutable receipt alone must not bless altered conversion output.
				receipt.Skills[0].SkillSHA256 = hashBytes(altered)
			case "unverified import claim":
				c.Skills[0].Provenance = "provenance-unverified"
				c.Skills[0].ImportPolicy = "metadata-only"
				catalogHash, err := CatalogDigest(c)
				if err != nil {
					t.Fatal(err)
				}
				receipt.CatalogSHA256 = catalogHash
			}
			data, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			writeImporterFile(t, receiptPath, data)
			report, err := Inspect(c, library)
			if err != nil {
				t.Fatal(err)
			}
			if report.Skills[0].Imported != Mismatch {
				t.Fatalf("rewritten receipt blessed an untrusted import claim: %+v", report.Skills[0])
			}
			assertOfflineEvidence(t, report)
		})
	}
}

func TestProviderDependencyMetadataDoesNotRequireFilesystem(t *testing.T) {
	c, _, _ := importerFixture(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(c, "")
	if err != nil {
		t.Fatal(err)
	}
	assertOfflineEvidence(t, report)
	for _, status := range report.Skills {
		if status.Imported != Missing {
			t.Fatalf("metadata inferred import without a library: %+v", status)
		}
	}
	for _, alias := range []string{"tool-stationery", "stationery", "STATIONERY"} {
		dependency, found := c.ResolveDependency(alias)
		if !found || dependency.ID != "tool-stationery" {
			t.Fatalf("explicit alias %q did not resolve: %+v", alias, dependency)
		}
	}
	for _, mention := range []string{"Bash", "must-not-connect", "Use stationery now", "unknown-command", " stationery "} {
		if dependency, found := c.ResolveDependency(mention); found {
			t.Fatalf("instruction mention %q inferred dependency %+v", mention, dependency)
		}
	}
}

func TestProviderDependencyAliasUsesValidationComparison(t *testing.T) {
	c, _, _ := importerFixture(t)
	c.Dependencies = []Dependency{{ID: "tool-ascii", Aliases: []string{"s"}}, {ID: "tool-unicode", Aliases: []string{"ſ"}}}
	for i := range c.Skills {
		c.Skills[i].Dependencies = nil
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for alias, want := range map[string]string{"s": "tool-ascii", "S": "tool-ascii", "ſ": "tool-unicode"} {
		got, ok := c.ResolveDependency(alias)
		if !ok || got.ID != want {
			t.Fatalf("alias %q resolved to %+v; want %s", alias, got, want)
		}
	}
}
