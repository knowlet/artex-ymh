package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Autumn-27/artex/skillprovider"
)

// This command is dispatched before server initialization: no DB migration,
// network listener, MCP connection or task runner is involved.
func runProvider(args []string) int {
	return providerCommand(context.Background(), args, os.Stdout, os.Stderr)
}
func providerCommand(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: artex provider <catalog|import|status> -catalog FILE [-source DIR -dest NEW_LIBRARY -select ID,ID | -library DIR]")
		return 2
	}
	action := args[0]
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
			err = encoder.Encode(map[string]any{"library": *dest, "imported_ids": ids, "agent_bindings_created": false, "runtime_verified": false})
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
