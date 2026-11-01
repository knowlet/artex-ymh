package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/xaioauth"
)

type subscriptionAuth interface {
	Start(context.Context) (*xaioauth.DeviceFlow, error)
	Wait(context.Context, *xaioauth.DeviceFlow) error
	Status() (xaioauth.Status, error)
	Logout(context.Context) error
}

func runAuthCLI(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAuth(ctx, args, os.Stdout, os.Stderr)
}

func runAuth(ctx context.Context, args []string, out, errOut io.Writer) int {
	return runAuthWithFactory(ctx, args, out, errOut, func(path string) subscriptionAuth {
		return xaioauth.NewManager(path)
	})
}

func runAuthWithFactory(ctx context.Context, args []string, out, errOut io.Writer, factory func(string) subscriptionAuth) int {
	const usage = "usage: artex auth login|status|logout xai-oauth [--key-dir DIR] [--data DIR]"
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, usage)
		return 0
	}
	if len(args) < 2 || args[1] != xaioauth.Provider ||
		(args[0] != "login" && args[0] != "status" && args[0] != "logout") {
		fmt.Fprintln(errOut, usage)
		return 2
	}
	fs := flag.NewFlagSet("auth "+args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	keyDefault := strings.TrimSpace(os.Getenv("ARTEX_KEY_DIR"))
	if keyDefault == "" {
		keyDefault = config.BaseDir()
	}
	keyDir := fs.String("key-dir", keyDefault, "private key location used by the server (ARTEX_KEY_DIR or executable directory)")
	dataDir := fs.String("data", filepath.Join(config.BaseDir(), "data"), "server data directory, used to reject browsable credential locations")
	if err := fs.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, usage)
		return 2
	}
	path, err := subscriptionStorePath(*keyDir, *dataDir, args[0] == "login")
	if err != nil {
		fmt.Fprintln(errOut, "Grok OAuth:", err)
		return 1
	}
	manager := factory(path)
	switch args[0] {
	case "status":
		status, err := manager.Status()
		if err != nil {
			fmt.Fprintln(errOut, "Grok OAuth:", err)
			return 1
		}
		if err := json.NewEncoder(out).Encode(status); err != nil {
			fmt.Fprintln(errOut, "write status:", err)
			return 1
		}
	case "logout":
		if err := manager.Logout(ctx); err != nil {
			fmt.Fprintln(errOut, "Grok OAuth:", err)
			return 1
		}
		fmt.Fprintln(out, "Grok subscription signed out locally. Revoke remote access in your xAI account settings if needed.")
	case "login":
		flow, err := manager.Start(ctx)
		if err != nil {
			fmt.Fprintln(errOut, "Grok OAuth:", err)
			return 1
		}
		verification := flow.VerificationURIComplete
		if verification == "" {
			verification = flow.VerificationURI
		}
		fmt.Fprintf(out, "Open %s\nUser code: %s\nApprove access in the browser. Press Ctrl+C to cancel.\n", verification, flow.UserCode)
		if err := manager.Wait(ctx, flow); err != nil {
			fmt.Fprintln(errOut, "Grok OAuth:", err)
			return 1
		}
		fmt.Fprintln(out, "Grok subscription connected. Select Grok subscription (OAuth) in LLM settings. Model access and quota are determined by xAI.")
	}
	return 0
}

// Store subscription tokens beside the JWT key, in their own private directory.
// A status check must not create credential files or initialize the service.
func subscriptionStorePath(keyDir, dataDir string, create bool) (string, error) {
	keyDir, err := filepath.Abs(keyDir)
	if err != nil {
		return "", err
	}
	keyDir, err = filepath.EvalSymlinks(keyDir)
	if err != nil {
		return "", fmt.Errorf("key directory must already exist: %w", err)
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return "", err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(dataDir); resolveErr == nil {
		dataDir = resolved
	} else if !os.IsNotExist(resolveErr) {
		return "", resolveErr
	}
	if rel, err := filepath.Rel(dataDir, keyDir); err == nil && (rel == "." || filepath.IsLocal(rel)) {
		return "", fmt.Errorf("key directory must be outside the browsable data directory")
	}
	dir := filepath.Join(keyDir, "xai-oauth")
	if create {
		if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
			return "", fmt.Errorf("OAuth directory must be a private directory (0700 on Unix), not a symlink")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return filepath.Join(dir, "session.json"), nil
}
