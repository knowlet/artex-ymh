package skillprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

func TestProviderPreservesDocumentLicenseAndCRLFBody(t *testing.T) {
	c, source, destination := importerFixture(t)
	body := "\r\n# Fictional stationery\r\nCopyright local fixture authors.\r\n"
	md := []byte("---\r\nname: harmless\r\ndescription: Harmless fixture.\r\nlicense: Apache-2.0\r\nmcps: [never-connect]\r\n---\r\n" + body)
	c.Skills[0].SourceSHA256 = hashBytes(md)
	c.Skills[0].SourceBytes = int64(len(md))
	writeImporterFile(t, filepath.Join(source, filepath.FromSlash(c.Skills[0].SourcePath)), md)
	if err := Import(context.Background(), c, source, destination, []string{"normal"}); err != nil {
		t.Fatal(err)
	}
	name := SkillName(c, c.Skills[0])
	generated := readImporterFile(t, filepath.Join(destination, name, "SKILL.md"))
	if !bytes.HasSuffix(generated, []byte(body)) {
		t.Fatal("CRLF body bytes changed")
	}
	reg, err := skill.LoadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := reg.Get(name)
	if !ok || s.License != "Apache-2.0" || len(s.MCPs) != 0 {
		t.Fatalf("document license lost or MCP activated: %+v", s)
	}
	if got := readImporterFile(t, filepath.Join(destination, name, "references", "LICENSE")); string(got) != syntheticLicense {
		t.Fatal("root notice lost")
	}
	if got := readImporterFile(t, filepath.Join(destination, name, "references", "source.md")); !bytes.Equal(got, md) {
		t.Fatal("original document notice lost")
	}
}

func TestProviderRejectsCaseVariantJSONFieldShadowing(t *testing.T) {
	c, _, _ := importerFixture(t)
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		bytes.Replace(b, []byte(`"provider":`), []byte(`"Provider":`), 1),
		bytes.Replace(b, []byte(`"provider":`), []byte(`"Provider":"shadow","provider":`), 1),
	} {
		if _, err := ParseCatalog(bytes.NewReader(raw)); err == nil {
			t.Fatal("case variant shadowing accepted")
		}
	}
}

type stageCancellationContext struct {
	context.Context
	cancel context.CancelFunc
	parent string
}

func (c stageCancellationContext) Err() error {
	entries, _ := os.ReadDir(c.parent)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".provider-stage-") {
			c.cancel()
			break
		}
	}
	return c.Context.Err()
}

func TestProviderCancellationRemovesCreatedStaging(t *testing.T) {
	c, source, destination := importerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := stageCancellationContext{ctx, cancel, filepath.Dir(destination)}
	if err := Import(observed, c, source, destination, []string{"normal", "legacy"}); err != context.Canceled {
		t.Fatalf("got %v, want cancellation after staging creation", err)
	}
	assertImportAbsent(t, destination)
}
