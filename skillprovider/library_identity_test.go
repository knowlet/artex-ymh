package skillprovider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderLegacyLibraryIdentity(t *testing.T) {
	for _, library := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		if got, err := LibraryIdentity(library); err != nil || got != "" {
			t.Fatalf("legacy identity=%q: %v", got, err)
		}
	}
}

func TestProviderReceiptRequiresUniqueLibraryIdentity(t *testing.T) {
	for _, id := range []string{"", "short", strings.Repeat("A", 32), strings.Repeat("0", 32), strings.Repeat("a", 33)} {
		raw, err := json.Marshal(Receipt{SchemaVersion: SchemaVersion, LibraryID: id})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseReceipt(raw); err == nil {
			t.Fatalf("invalid library identity %q accepted", id)
		}
	}
	raw := []byte(`{"schema_version":1,"library_id":"` + strings.Repeat("a", 32) + `"}`)
	if _, err := parseReceipt(raw); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), []byte(`{"schema_version":1,"library_id":"` + strings.Repeat("a", 32) + `","library_id":"` + strings.Repeat("b", 32) + `"}`)} {
		if _, err := parseReceipt(invalid); err == nil {
			t.Fatal("duplicate or trailing receipt object accepted")
		}
	}
}

func TestProviderNewImportsHaveDistinctLibraryIdentities(t *testing.T) {
	requireLinuxFS(t)
	catalog, source, first := importerFixture(t)
	second := filepath.Join(t.TempDir(), "second")
	if err := Import(context.Background(), catalog, source, first, []string{"normal"}); err != nil {
		t.Fatal(err)
	}
	if err := Import(context.Background(), catalog, source, second, []string{"normal"}); err != nil {
		t.Fatal(err)
	}
	firstID, err := LibraryIdentity(first)
	if err != nil || firstID == "" {
		t.Fatalf("first identity=%q: %v", firstID, err)
	}
	secondID, err := LibraryIdentity(second)
	if err != nil || secondID == "" || firstID == secondID {
		t.Fatalf("new import reused identity %q: %v", secondID, err)
	}
	if err := os.Remove(filepath.Join(second, ReceiptFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := LibraryIdentity(second); err == nil {
		t.Fatal("missing provider receipt downgraded to legacy library")
	}
	if err := os.WriteFile(filepath.Join(first, ReceiptFilename), []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LibraryIdentity(first); err == nil {
		t.Fatal("old receipt without identity accepted")
	}
	if _, err := Inspect(catalog, first); err == nil {
		t.Fatal("old receipt certified import")
	}
}
