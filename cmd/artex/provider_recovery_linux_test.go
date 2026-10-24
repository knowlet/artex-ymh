//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProviderCLIRecoverExactRecognizedStage(t *testing.T) {
	for _, failOutput := range []bool{false, true} {
		t.Run(map[bool]string{false: "reported", true: "output-failed"}[failOutput], func(t *testing.T) {
			name := ".provider-stage-" + strings.Repeat("a", 32)
			stage := filepath.Join(t.TempDir(), name)
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			var st unix.Stat_t
			if err := unix.Stat(stage, &st); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte("{}"))
			data, err := json.Marshal(map[string]any{
				"version": 1, "name": name, "device": uint64(st.Dev), "inode": st.Ino,
				"files": []map[string]any{{"path": "library/.provider-import.json", "bytes": 2, "sha256": hex.EncodeToString(sum[:])}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stage, ".provider-stage.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			var writer io.Writer = &out
			if failOutput {
				writer = failingRecoveryWriter{}
			}
			code := providerCommand(context.Background(), []string{"recover", "-stage", stage}, writer, &stderr)
			if failOutput {
				if code != providerExitCommittedOutputFailed || !strings.Contains(stderr.String(), "recovered=true") {
					t.Fatalf("exit=%d stderr=%s", code, &stderr)
				}
			} else if code != 0 || !strings.Contains(out.String(), `"recovered":true`) {
				t.Fatalf("exit=%d out=%s stderr=%s", code, &out, &stderr)
			}
			if _, err := os.Lstat(stage); !os.IsNotExist(err) {
				t.Fatal("recognized inactive stage remained")
			}
		})
	}
}

type failingRecoveryWriter struct{}

func (failingRecoveryWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestProviderCLIRecoverInvalidArgumentsAndForeignContent(t *testing.T) {
	for _, args := range [][]string{
		{"recover"}, {"recover", "-stage", "x", "extra"}, {"recover", "-catalog", "x"},
	} {
		code, out, stderr := callProviderCLI(t, args...)
		if code != 2 || len(out) != 0 || stderr == "" {
			t.Fatalf("args=%v exit=%d out=%s err=%s", args, code, out, stderr)
		}
	}
	stage := filepath.Join(t.TempDir(), ".provider-stage-"+strings.Repeat("a", 32))
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	user := filepath.Join(stage, "USER")
	if err := os.WriteFile(user, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := callProviderCLI(t, "recover", "-stage", stage)
	if code != 1 || len(out) != 0 {
		t.Fatalf("foreign stage accepted: %d %s", code, out)
	}
	if data, err := os.ReadFile(user); err != nil || string(data) != "preserve" {
		t.Fatal("foreign user content changed")
	}
}
