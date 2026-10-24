//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Autumn-27/artex/skillprovider"
)

// This test-only context sends a real signal after staging through the exact
// signal wrapper used by runProvider, without a polling race or production hook.
type providerStageSignalContext struct {
	context.Context
	parent  string
	signal  syscall.Signal
	sent    bool
	failure error
}

func (c *providerStageSignalContext) Err() error {
	if !c.sent {
		entries, err := os.ReadDir(c.parent)
		if err != nil {
			c.failure = err
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".provider-stage-") {
				continue
			}
			c.sent = true
			if err := syscall.Kill(os.Getpid(), c.signal); err != nil {
				c.failure = err
				return err
			}
			select {
			case <-c.Context.Done():
			case <-time.After(5 * time.Second):
				c.failure = fmt.Errorf("signal did not cancel provider context")
				return c.failure
			}
			break
		}
	}
	return c.Context.Err()
}

// The helper executes only our harmless CLI fixture in an isolated test process.
func TestProviderProcessHelper(t *testing.T) {
	mode := os.Getenv("ARTEX_PROVIDER_PROCESS_MODE")
	if mode == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("ARTEX_PROVIDER_PROCESS_ARGS")), &args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(99)
	}
	if mode == "closed-pipe" {
		os.Exit(runProvider(args))
	}
	sig := syscall.SIGTERM
	if mode == "interrupt" {
		sig = syscall.SIGINT
	} else if mode == "kill" {
		sig = syscall.SIGKILL
	} else if mode != "terminate" {
		os.Exit(99)
	}
	code := withProviderSignals(func(ctx context.Context) int {
		watched := &providerStageSignalContext{Context: ctx, parent: os.Getenv("ARTEX_PROVIDER_PROCESS_PARENT"), signal: sig}
		code := providerCommand(watched, args, os.Stdout, os.Stderr)
		if !watched.sent || watched.failure != nil || !errors.Is(ctx.Err(), context.Canceled) {
			fmt.Fprintf(os.Stderr, "signal helper failed: sent=%v err=%v context=%v\n", watched.sent, watched.failure, ctx.Err())
			return 99
		}
		return code
	})
	os.Exit(code)
}

func newProviderProcess(t *testing.T, mode, library string, args []string) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProviderProcessHelper$")
	cmd.Env = append(os.Environ(), "ARTEX_PROVIDER_PROCESS_MODE="+mode, "ARTEX_PROVIDER_PROCESS_ARGS="+string(encoded), "ARTEX_PROVIDER_PROCESS_PARENT="+filepath.Dir(library))
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	return cmd, &out, &stderr
}

func TestProviderCLISignalsCleanStaging(t *testing.T) {
	for _, mode := range []string{"interrupt", "terminate"} {
		t.Run(mode, func(t *testing.T) {
			catalog, source, library := providerCLIFixture(t)
			args := []string{"import", "-catalog", catalog, "-source", source, "-dest", library, "-select", "notes"}
			cmd, out, stderr := newProviderProcess(t, mode, library, args)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(stderr.String(), "context canceled") || out.Len() != 0 {
				t.Fatalf("signal did not unwind import: err=%v out=%s stderr=%s", err, out, stderr)
			}
			if _, err := os.Lstat(library); !os.IsNotExist(err) {
				t.Fatalf("canceled import published: %v", err)
			}
			entries, err := os.ReadDir(filepath.Dir(library))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".provider-stage-") {
					t.Fatalf("signal left staging %s", entry.Name())
				}
			}
		})
	}
}

func TestProviderCLIClosedPipeReportsCommitted(t *testing.T) {
	catalogPath, source, library := providerCLIFixture(t)
	args := []string{"import", "-catalog", catalogPath, "-source", source, "-dest", library, "-select", "notes"}
	cmd, _, stderr := newProviderProcess(t, "closed-pipe", library, args)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	cmd.Stdout = write
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != providerExitCommittedOutputFailed || !strings.Contains(stderr.String(), "committed=true") || !strings.Contains(stderr.String(), library) {
		t.Fatalf("closed stdout lost commit state: err=%v stderr=%s", err, stderr)
	}
	catalog, err := skillprovider.LoadCatalogFile(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := skillprovider.Inspect(catalog, library)
	if err != nil || report.Skills[0].Imported != skillprovider.Verified {
		t.Fatalf("closed pipe lost committed library: %+v %v", report, err)
	}
}

func TestProviderCLIKillLeavesStagingWithoutAutomaticDeletion(t *testing.T) {
	catalog, source, library := providerCLIFixture(t)
	args := []string{"import", "-catalog", catalog, "-source", source, "-dest", library, "-select", "notes"}
	cmd, _, stderr := newProviderProcess(t, "kill", library, args)
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("kill did not terminate helper: %v %s", err, stderr)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected helper termination: %v %s", err, stderr)
	}
	if _, err := os.Lstat(library); !os.IsNotExist(err) {
		t.Fatalf("killed import published: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(library))
	if err != nil {
		t.Fatal(err)
	}
	var stage string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".provider-stage-") {
			if stage != "" {
				t.Fatal("multiple staging directories")
			}
			stage = filepath.Join(filepath.Dir(library), entry.Name())
		}
	}
	if stage == "" {
		t.Fatal("SIGKILL fixture did not leave expected staging")
	}
	marker := filepath.Join(stage, "USER")
	if err := os.WriteFile(marker, []byte("retain operator-owned content"), 0600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(filepath.Dir(library), "new-library")
	code, _, newErr := callProviderCLI(t, "import", "-catalog", catalog, "-source", source, "-dest", fresh, "-select", "notes")
	if code != 0 {
		t.Fatalf("fresh import failed: %s", newErr)
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "retain operator-owned content" {
		t.Fatalf("later import touched residual/user data: %q %v", content, err)
	}
}
