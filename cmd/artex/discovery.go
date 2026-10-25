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
	"syscall"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/discovery"
)

type templateFlags []string

func (f *templateFlags) String() string { return fmt.Sprint([]string(*f)) }
func (f *templateFlags) Set(s string) error {
	*f = append(*f, s)
	return nil
}

func runDiscoveryCLI(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runDiscovery(ctx, args, os.Stdout, os.Stderr)
}

// runDiscovery keeps planning and execution separate so a missing action never
// starts network traffic. stdout is plan JSON or the tool's native JSONL only.
func runDiscovery(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || (args[0] != "plan" && args[0] != "run") {
		fmt.Fprintln(errOut, "usage: artex discovery plan|run --tool NAME --target TARGET [--profile low-noise|standard|passive]")
		return 2
	}
	fs := flag.NewFlagSet("discovery "+args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	opts := discovery.Options{}
	var templates templateFlags
	var reportPath string
	fs.StringVar(&opts.Tool, "tool", "", "httpx, katana, naabu, subfinder, or nuclei")
	fs.StringVar(&opts.Target, "target", "", "one explicit URL or host, depending on tool")
	fs.StringVar(&opts.Profile, "profile", "low-noise", "low-noise, standard, or passive (subfinder only)")
	fs.StringVar(&opts.ToolsDir, "tools-dir", filepath.Join(config.BaseDir(), "data", "tools"), "directory containing reviewed tool binaries")
	fs.StringVar(&opts.TemplatesDir, "templates-dir", "", "reviewed Nuclei template directory")
	fs.Var(&templates, "template", "relative Nuclei template file; repeat to select multiple files")
	fs.DurationVar(&opts.Timeout, "timeout", 2*time.Minute, "whole subprocess timeout, at most 1h")
	fs.StringVar(&reportPath, "report", "", "optional JSON execution receipt (run only); must not already exist")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || (args[0] == "plan" && reportPath != "") {
		fmt.Fprintln(errOut, "unexpected positional arguments or --report on plan")
		return 2
	}
	opts.Templates = templates
	var pathErr error
	opts.ToolsDir, pathErr = filepath.Abs(opts.ToolsDir)
	if pathErr != nil {
		fmt.Fprintln(errOut, "resolve tools directory:", pathErr)
		return 2
	}
	if opts.TemplatesDir != "" {
		opts.TemplatesDir, pathErr = filepath.Abs(opts.TemplatesDir)
		if pathErr != nil {
			fmt.Fprintln(errOut, "resolve templates directory:", pathErr)
			return 2
		}
	}
	plan, err := discovery.BuildPlan(opts)
	if err != nil {
		fmt.Fprintln(errOut, "discovery:", err)
		return 2
	}
	if args[0] == "plan" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(plan); err != nil {
			fmt.Fprintln(errOut, "write plan:", err)
			return 1
		}
		return 0
	}

	// Reserve the receipt before running. A bad path or existing file must not
	// cause traffic and must never overwrite another run's evidence.
	var report *os.File
	if reportPath != "" {
		report, err = os.OpenFile(reportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			fmt.Fprintln(errOut, "create report:", err)
			return 1
		}
	}
	started := time.Now().UTC()
	if report != nil {
		// Persist a running receipt before dispatch, so SIGKILL/crashes leave an
		// explicitly incomplete artifact instead of an empty success-looking file.
		err = json.NewEncoder(report).Encode(map[string]any{
			"plan": plan, "started_at": started, "status": "running",
			"coverage": "unknown", "findings_validation": "unverified",
		})
		if err == nil {
			err = report.Sync()
		}
		if err != nil {
			report.Close()
			fmt.Fprintln(errOut, "write running report:", err)
			return 1
		}
	}
	err = discovery.Run(ctx, opts, out, errOut)
	status, code := "process_exited", 0
	if err != nil {
		status, code = "failed", 1
		if errors.Is(err, context.DeadlineExceeded) {
			status, code = "timed_out", 124
		} else if errors.Is(err, context.Canceled) {
			status, code = "cancelled", 130
		}
		fmt.Fprintln(errOut, "discovery:", err)
	}
	if report != nil {
		receipt := map[string]any{
			"plan": plan, "started_at": started, "finished_at": time.Now().UTC(),
			"status": status, "exit_code": code,
			"coverage": "unknown", "findings_validation": "unverified",
		}
		if err != nil {
			receipt["error"] = err.Error()
		}
		// Keep the running receipt intact if serialization fails. Write a sibling
		// temp file, sync, then replace only the file reserved by this invocation.
		if e := finishDiscoveryReport(report, receipt); e != nil {
			fmt.Fprintln(errOut, "write final report (run may have executed):", e)
			if code == 0 {
				code = 1
			}
		}
	}
	return code
}

func finishDiscoveryReport(f *os.File, receipt map[string]any) error {
	defer f.Close()
	b, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	// The receipt is a user-selected local artifact, not a security boundary
	// against concurrent local directory mutations.
	tmp, err := os.CreateTemp(filepath.Dir(f.Name()), ".discovery-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Name())
}
