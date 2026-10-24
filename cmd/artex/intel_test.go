package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func shippedIntelPack(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path unavailable")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "packaging", "discovery-data-manifest.json")
}

func TestIntelExplicitActionAndUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"run"}, {"status", "--query", "x"}, {"search", "--unknown"}, {"status", "extra"}, {"status", "--help"}} {
		var out, errs bytes.Buffer
		got := runIntel(args, &out, &errs)
		want := 2
		if len(args) == 2 && args[1] == "--help" {
			want = 0
		}
		if got != want || out.Len() != 0 {
			t.Fatalf("%v: code=%d out=%s err=%s", args, got, &out, &errs)
		}
	}
}

func TestIntelStatusAndBoundedSearch(t *testing.T) {
	pack := shippedIntelPack(t)
	for _, args := range [][]string{
		{"status", "--data-pack", pack},
		{"search", "--data-pack", pack, "--vendor", "Microsoft", "--limit", "2"},
		{"search", "--data-pack", pack, "--cve", "CVE-2999-9999999999999999999"},
	} {
		var out, errs bytes.Buffer
		if code := runIntel(args, &out, &errs); code != 0 {
			t.Fatalf("%v code%d %s", args, code, &errs)
		}
		var result map[string]any
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if args[0] == "status" {
			if result["freshness"] != "not-checked-online" || result["kev_count"].(float64) < 1 {
				t.Fatalf("status:%s", &out)
			}
		} else if result["target_vulnerability"] != "unverified" || result["returned_kev_matches"].(float64) > 2 {
			t.Fatalf("search:%s", &out)
		}
	}
}

func TestIntelInvalidDataAndQueryReturnNonzero(t *testing.T) {
	pack := shippedIntelPack(t)
	for _, args := range [][]string{
		{"search", "--data-pack", pack},
		{"search", "--data-pack", pack, "--cve", "CVE-*"},
		{"search", "--data-pack", pack, "--query", "x", "--limit", "101"},
		{"search", "--data-pack", pack, "--query", "x", "--limit", "0"},
		{"status", "--data-pack", filepath.Join(t.TempDir(), "missing")},
	} {
		var out, errs bytes.Buffer
		if code := runIntel(args, &out, &errs); code == 0 || out.Len() != 0 {
			t.Fatalf("invalid call accepted %v: %d/%s", args, code, &out)
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := runIntel([]string{"status", "--data-pack", bad}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "invalid") {
		t.Fatalf("code=%d errs=%s", code, &errs)
	}
}

type closedIntelWriter struct{}

func (closedIntelWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestIntelOutputFailureIsNotSuccess(t *testing.T) {
	var errs bytes.Buffer
	if code := runIntel([]string{"status", "--data-pack", shippedIntelPack(t)}, closedIntelWriter{}, &errs); code != 1 {
		t.Fatalf("code=%d err=%s", code, &errs)
	}
}
