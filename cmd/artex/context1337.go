package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Autumn-27/artex/context1337"
)

func runContext1337CLI(args []string) int {
	return runContext1337(context.Background(), args, os.Getenv, os.Stdout, os.Stderr)
}

func runContext1337(ctx context.Context, args []string, getenv func(string) string, out, errOut io.Writer) int {
	if len(args) == 0 || (args[0] != "status" && args[0] != "search") {
		fmt.Fprintln(errOut, "usage: artex context1337 status | search --cve ID [--source builtin|nuclei]")
		return 2
	}
	fs := flag.NewFlagSet("context1337 "+args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	cve := fs.String("cve", "", "one complete CVE ID")
	source := fs.String("source", "builtin", "builtin or nuclei")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || (args[0] == "status" && fs.NFlag() != 0) ||
		(args[0] == "search" && (!context1337.ValidCVE(*cve) || (*source != "builtin" && *source != "nuclei"))) {
		fmt.Fprintln(errOut, "context1337: invalid action arguments")
		return 2
	}
	client, err := context1337.NewClient(getenv("ARTEX_CONTEXT1337_URL"), getenv("ARTEX_CONTEXT1337_API_KEY"))
	if err != nil {
		fmt.Fprintln(errOut, "context1337:", err)
		return 1
	}
	var result any
	if args[0] == "status" {
		result, err = client.Status(ctx)
	} else {
		result, err = client.Search(ctx, *cve, *source)
	}
	if err != nil {
		fmt.Fprintln(errOut, "context1337:", err)
		return 1
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(errOut, "context1337: unable to write output")
		return 1
	}
	return 0
}
