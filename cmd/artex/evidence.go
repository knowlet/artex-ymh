package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

const maxHARBytes = 16 << 20

type harCount struct {
	Method string `json:"method"`
	Status int    `json:"status"`
	Count  int    `json:"count"`
}

type harSummary struct {
	Mode    string     `json:"mode"`
	Entries int        `json:"entries"`
	Counts  []harCount `json:"counts"`
}

func runEvidenceCLI(args []string) int {
	return runEvidence(args, os.Stdin, os.Stdout, os.Stderr)
}

// runEvidence projects a local HAR to aggregate counts. It never starts the
// service, contacts a network, opens other files, or emits captured text.
func runEvidence(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) != 1 || args[0] != "har-summary" {
		fmt.Fprintln(errOut, "usage: artex evidence har-summary < capture.har")
		return 2
	}
	data, err := io.ReadAll(io.LimitReader(in, maxHARBytes+1))
	if err != nil || len(data) > maxHARBytes {
		fmt.Fprintln(errOut, "evidence: unreadable or oversized HAR (16 MiB maximum)")
		return 1
	}
	var doc struct {
		Log *struct {
			Entries *[]struct {
				Request *struct {
					Method string `json:"method"`
				} `json:"request"`
				Response *struct {
					Status *int `json:"status"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	// Do not echo parser errors: field names and values may be sensitive.
	if json.Unmarshal(data, &doc) != nil || doc.Log == nil || doc.Log.Entries == nil {
		fmt.Fprintln(errOut, "evidence: invalid HAR structure")
		return 1
	}
	type key struct {
		method string
		status int
	}
	counts := map[key]int{}
	for _, entry := range *doc.Log.Entries {
		if entry.Request == nil || entry.Request.Method == "" || entry.Response == nil || entry.Response.Status == nil {
			fmt.Fprintln(errOut, "evidence: missing request method or response status")
			return 1
		}
		status := *entry.Response.Status
		if status != 0 && (status < 100 || status > 599) {
			fmt.Fprintln(errOut, "evidence: invalid HTTP status")
			return 1
		}
		// Custom HTTP methods may contain arbitrary data. Never reflect them.
		method := "OTHER"
		switch entry.Request.Method {
		case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH":
			method = entry.Request.Method
		}
		counts[key{method, status}]++
	}
	result := harSummary{Mode: "aggregate-metadata-only", Entries: len(*doc.Log.Entries), Counts: []harCount{}}
	for k, count := range counts {
		result.Counts = append(result.Counts, harCount{k.method, k.status, count})
	}
	sort.Slice(result.Counts, func(i, j int) bool {
		if result.Counts[i].Method != result.Counts[j].Method {
			return result.Counts[i].Method < result.Counts[j].Method
		}
		return result.Counts[i].Status < result.Counts[j].Status
	})
	if json.NewEncoder(out).Encode(result) != nil {
		fmt.Fprintln(errOut, "evidence: unable to write summary")
		return 1
	}
	return 0
}
