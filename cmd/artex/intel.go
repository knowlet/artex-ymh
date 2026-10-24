package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/intelpack"
)

func runIntelCLI(args []string) int { return runIntel(args, os.Stdout, os.Stderr) }

// runIntel never starts the service, downloads data, or executes tools.
func runIntel(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || (args[0] != "status" && args[0] != "search") {
		fmt.Fprintln(errOut, "usage: artex intel status|search [--data-pack PATH] [--cve ID|--vendor TEXT|--product TEXT|--query TEXT] [--limit 20]")
		return 2
	}
	fs := flag.NewFlagSet("intel "+args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	manifest := fs.String("data-pack", filepath.Join(config.BaseDir(), "packaging", "discovery-data-manifest.json"), "offline intelligence manifest")
	var q intelpack.Query
	fs.StringVar(&q.CVE, "cve", "", "one complete CVE ID")
	fs.StringVar(&q.Vendor, "vendor", "", "case-insensitive KEV vendor substring")
	fs.StringVar(&q.Product, "product", "", "case-insensitive KEV product substring")
	fs.StringVar(&q.Text, "query", "", "case-insensitive KEV CVE/vendor/product/title/description substring")
	fs.IntVar(&q.Limit, "limit", intelpack.DefaultLimit, "maximum results per collection (1-100)")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "intel: unexpected positional arguments")
		return 2
	}
	if args[0] == "status" {
		invalid := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name != "data-pack" {
				invalid = true
			}
		})
		if invalid {
			fmt.Fprintln(errOut, "intel status accepts --data-pack only")
			return 2
		}
	}
	if args[0] == "search" && (q.Limit < 1 || q.Limit > intelpack.MaxLimit) {
		fmt.Fprintln(errOut, "intel: limit must be between 1 and 100")
		return 2
	}
	pack, err := intelpack.Load(*manifest)
	if err != nil {
		fmt.Fprintln(errOut, "intel: data pack unavailable or invalid:", err)
		return 1
	}
	var result any
	if args[0] == "status" {
		result = pack.Status(time.Now().UTC())
	} else {
		result, err = pack.Search(q)
		if err != nil {
			fmt.Fprintln(errOut, "intel:", err)
			return 2
		}
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(errOut, "intel: write output:", err)
		return 1
	}
	return 0
}
