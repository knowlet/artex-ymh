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
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"run", "--target", "https://not-authorized.invalid"}, &out, &errOut); code != 2 {
		t.Fatalf("code=%d out=%s err=%s", code, &out, &errOut)
	}
}
