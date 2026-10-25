package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Autumn-27/artex/skillprovider"
)

// This command is dispatched before server initialization: no DB migration,
// network listener, MCP connection or task runner is involved.
func runProvider(args []string) int {
	return withProviderSignals(func(ctx context.Context) int {
		return providerCommand(ctx, args, os.Stdout, os.Stderr)
	})
}

// Catch ordinary operator interruption so Import can unwind its staging files.
// SIGPIPE is handled separately: a closed stdout must become an output error,
// rather than terminate the process after a library has already been committed.
func withProviderSignals(run func(context.Context) int) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pipe := make(chan os.Signal, 1)
	signal.Notify(pipe, syscall.SIGPIPE)
	defer signal.Stop(pipe)
	return run(ctx)
}

const providerExitCommittedOutputFailed = 3

func providerCommand(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: artex provider <catalog|import|status> -catalog FILE [-source DIR -dest NEW_LIBRARY -select ID,ID | -library DIR]; artex provider recover -stage EXACT_STAGE_PATH")
		return 2
	}
	action := args[0]
	if action == "recover" {
		return providerRecoverCommand(ctx, args[1:], out, errOut)
	}
	if action != "catalog" && action != "import" && action != "status" {
		fmt.Fprintln(errOut, "unknown provider action")
		return 2
	}
	flags := flag.NewFlagSet("provider "+action, flag.ContinueOnError)
	flags.SetOutput(errOut)
	catalogPath := flags.String("catalog", "", "reviewed schema-1 catalog JSON")
	source := flags.String("source", "", "local pinned source directory (no downloads)")
	dest := flags.String("dest", "", "new library path; existing destinations are refused")
	selection := flags.String("select", "", "explicit comma-separated catalog skill IDs")
	library := flags.String("library", "", "local library for receipt/hash inspection")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *catalogPath == "" {
		fmt.Fprintln(errOut, "-catalog is required; positional arguments are not accepted")
		return 2
	}
	catalog, err := skillprovider.LoadCatalogFile(*catalogPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	switch action {
	case "catalog":
		err = encoder.Encode(catalog)
	case "import":
		if *source == "" || *dest == "" || *selection == "" {
			fmt.Fprintln(errOut, "import requires -source, -dest and explicit -select")
			return 2
		}
		ids := strings.Split(*selection, ",")
		for i := range ids {
			ids[i] = strings.TrimSpace(ids[i])
		}
		err = skillprovider.Import(ctx, catalog, *source, *dest, ids)
		if err == nil {
			err = encoder.Encode(map[string]any{"committed": true, "library": *dest, "imported_ids": ids, "agent_bindings_created": false, "agent_visible": "unknown", "runtime_verified": false})
			if err != nil {
				fmt.Fprintf(errOut, "committed=true: import committed to %q, but success output failed: %v; do not retry this destination; inspect it with provider status before further action\n", *dest, err)
				return providerExitCommittedOutputFailed
			}
		}
	case "status":
		var report *skillprovider.ReadinessReport
		report, err = skillprovider.Inspect(catalog, *library)
		if err == nil {
			err = encoder.Encode(report)
		}
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func providerRecoverCommand(ctx context.Context, args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("provider recover", flag.ContinueOnError)
	flags.SetOutput(errOut)
	stage := flags.String("stage", "", "exact interrupted staging directory; changed or unknown content is preserved")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *stage == "" {
		fmt.Fprintln(errOut, "recover requires -stage EXACT_STAGE_PATH and no positional arguments")
		return 2
	}
	if err := skillprovider.RecoverStage(ctx, *stage); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if err := json.NewEncoder(out).Encode(map[string]any{"recovered": true, "stage": *stage}); err != nil {
		fmt.Fprintf(errOut, "recovered=true: staging cleanup completed, but success output failed: %v\n", err)
		return providerExitCommittedOutputFailed
	}
	return 0
}
