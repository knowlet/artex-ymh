package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func discoveryFixture(t *testing.T, content string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX subprocess fixture")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "httpx"), []byte("#!/bin/sh\n"+content), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDiscoveryRequiresExplicitAction(t *testing.T) {
	for _, args := range [][]string{nil, {"--tool", "httpx"}, {"install"}, {"plan", "--help"}, {"run", "--unknown"}} {
		var out, errs bytes.Buffer
		got := runDiscovery(context.Background(), args, &out, &errs)
		want := 2
		if len(args) == 2 && args[1] == "--help" {
			want = 0
		}
		if got != want || out.Len() != 0 {
			t.Fatalf("%v: exit %d, stdout %q", args, got, out.String())
		}
	}
}

func TestDiscoveryPlanDoesNotExecute(t *testing.T) {
	dir := discoveryFixture(t, "exit 42\n")
	var out, errs bytes.Buffer
	code := runDiscovery(context.Background(), []string{"plan", "--tool", "httpx", "--target", "https://example.invalid/", "--tools-dir", dir}, &out, &errs)
	if code != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("exit=%d, out=%s, err=%s", code, &out, &errs)
	}
}

func TestDiscoveryReceiptSeparatesProcessAndCoverage(t *testing.T) {
	dir := discoveryFixture(t, "echo '{\"candidate\":true}'\n")
	report := filepath.Join(t.TempDir(), "receipt.json")
	var out, errs bytes.Buffer
	code := runDiscovery(context.Background(), []string{"run", "--tool", "httpx", "--target", "https://example.invalid/", "--tools-dir", dir, "--report", report}, &out, &errs)
	if code != 0 || !json.Valid(bytes.TrimSpace(out.Bytes())) {
		t.Fatalf("exit=%d, out=%s, err=%s", code, &out, &errs)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["status"] != "process_exited" || receipt["coverage"] != "unknown" || receipt["findings_validation"] != "unverified" {
		t.Fatalf("false assurance in receipt: %s", raw)
	}
	st, _ := os.Stat(report)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode %o", st.Mode().Perm())
	}
}

func TestDiscoveryExistingReceiptPreventsExecution(t *testing.T) {
	dir := discoveryFixture(t, "echo ran\n")
	report := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(report, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := runDiscovery(context.Background(), []string{"run", "--tool", "httpx", "--target", "https://example.invalid/", "--tools-dir", dir, "--report", report}, &out, &errs)
	if code == 0 || out.Len() != 0 {
		t.Fatalf("execution despite receipt conflict: code=%d out=%s", code, &out)
	}
	b, _ := os.ReadFile(report)
	if string(b) != "existing" {
		t.Fatal("existing receipt overwritten")
	}
}

func TestDiscoveryFailedProcessReceipt(t *testing.T) {
	dir := discoveryFixture(t, "exit 7\n")
	report := filepath.Join(t.TempDir(), "receipt.json")
	var out, errs bytes.Buffer
	code := runDiscovery(context.Background(), []string{"run", "--tool", "httpx", "--target", "https://example.invalid/", "--tools-dir", dir, "--report", report}, &out, &errs)
	b, _ := os.ReadFile(report)
	var receipt map[string]any
	_ = json.Unmarshal(b, &receipt)
	if code == 0 || receipt["status"] != "failed" || receipt["error"] == nil {
		t.Fatalf("code=%d receipt=%s stderr=%s", code, b, &errs)
	}
}

func TestDiscoveryCancelledReceipt(t *testing.T) {
	dir := discoveryFixture(t, "echo must-not-execute\n")
	report := filepath.Join(t.TempDir(), "receipt.json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errs bytes.Buffer
	code := runDiscovery(ctx, []string{"run", "--tool", "httpx", "--target", "https://example.invalid/", "--tools-dir", dir, "--report", report}, &out, &errs)
	b, _ := os.ReadFile(report)
	var receipt map[string]any
	_ = json.Unmarshal(b, &receipt)
	if code != 130 || out.Len() != 0 || receipt["status"] != "cancelled" {
		t.Fatalf("code=%d out=%s receipt=%s stderr=%s", code, &out, b, &errs)
	}
}

func TestDiscoveryTimeoutReceipt(t *testing.T) {
	dir := discoveryFixture(t, "exec sleep 5\n")
	report := filepath.Join(t.TempDir(), "receipt.json")
	var out, errs bytes.Buffer
	code := runDiscovery(context.Background(), []string{"run", "--tool", "httpx", "--target", "https://example.invalid/", "--tools-dir", dir, "--timeout", "20ms", "--report", report}, &out, &errs)
	b, _ := os.ReadFile(report)
	var receipt map[string]any
	_ = json.Unmarshal(b, &receipt)
	if code != 124 || receipt["status"] != "timed_out" || receipt["coverage"] != "unknown" {
		t.Fatalf("code=%d receipt=%s stderr=%s", code, b, &errs)
	}
}
