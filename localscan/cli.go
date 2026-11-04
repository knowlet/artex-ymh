// Package localscan exposes the explicitly authorized, local-only scanner CLI.
// It does not register server/agent tools or change permissions.
package localscan

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

//go:embed worker.py
var worker []byte

//go:embed sources.lock.json
var sources []byte

// Run delegates to the bundled stdlib-only worker with isolated Python imports.
// The interpreter and sandbox helpers are explicitly required host dependencies.
func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fmt.Fprintln(errOut, "local scanning requires Linux amd64")
		return 2
	}
	dir, err := os.MkdirTemp("", "artex-scan-cli-")
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	defer os.RemoveAll(dir)
	for name, data := range map[string][]byte{"worker.py": worker, "sources.lock.json": sources} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o400); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	argv := append([]string{"-I", filepath.Join(dir, "worker.py")}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", argv...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = out, errOut
	cmd.WaitDelay = 3 * time.Second
	// Let Python kill/reap its process group and preserve an incomplete receipt.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() >= 0 {
			return exit.ExitCode()
		}
		fmt.Fprintln(errOut, "local scanner worker:", err)
		return 2
	}
	return 0
}
