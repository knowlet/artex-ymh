package localscan

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"testing"
)

func TestEmbeddedLock(t *testing.T) {
	var lock struct {
		Platform string         `json:"platform"`
		Bundled  map[string]any `json:"bundled"`
	}
	if err := json.Unmarshal(sources, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Platform != "linux/amd64" || len(lock.Bundled) != 2 {
		t.Fatal("unexpected embedded tool inventory")
	}
}

func TestHelpWithoutServiceInitialization(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"--help"}, &out, &errOut)
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		if code != 2 {
			t.Fatalf("unsupported platform code=%d", code)
		}
		return
	}
	if code != 0 || !bytes.Contains(out.Bytes(), []byte("seal-db")) {
		t.Fatalf("code=%d out=%s err=%s", code, &out, &errOut)
	}
}

func TestUnknownFlagsFailClosed(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("linux/amd64 only")
	}
	var out, errOut bytes.Buffer
	args := []string{
		"run", "--tool", "trivy", "--install-dir", "/tmp/scan-install", "--sbom", "/tmp/bom.json",
		"--db-dir", "/tmp/db", "--authorized", "--report-dir", "/tmp/report",
		"--target", "https://not-authorized.invalid",
	}
	if code := Run(context.Background(), args, &out, &errOut); code != 2 {
		t.Fatalf("code=%d out=%s err=%s", code, &out, &errOut)
	}
	if !bytes.Contains(errOut.Bytes(), []byte("unrecognized arguments")) {
		t.Fatalf("expected unknown-flag error, err=%s", &errOut)
	}
}
