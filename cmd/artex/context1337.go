package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	context1337MaxResponse = 512 << 10
	context1337PageLimit = 20
)

var context1337CVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

type context1337Client struct {
	endpoint *url.URL
	key string
	http *http.Client
}

// Configuration is operator-owned and has no defaults. Do not reuse the
// task HTTP proxy or allow arbitrary agent-selected destinations.
func newContext1337Client(endpoint, key string) (*context1337Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("ARTEX_CONTEXT1337_URL must be an HTTPS origin or literal loopback HTTP origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, errors.New("Context1337 requires HTTPS except on literal loopback")
	}
	if len(key) == 0 || len(key) > 4096 {
		return nil, errors.New("ARTEX_CONTEXT1337_API_KEY is required")
	}
	for _, ch := range key {
		if ch < 33 || ch > 126 {
			return nil, errors.New("invalid Context1337 API key")
		}
	}
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSHandshakeTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives: true,
		MaxResponseHeaderBytes: 32 << 10,
	}
	return &context1337Client{
		endpoint: u, key: key,
		http: &http.Client{
			Transport: transport, Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Only fixed GET routes are used. Error output never includes remote bodies,
// endpoint URLs, request headers, or credentials.
func (c *context1337Client) get(ctx context.Context, route string, query url.Values, out any) error {
	u := *c.endpoint
	u.Path = route
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("invalid Context1337 request")
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("Context1337 request failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Context1337 returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, context1337MaxResponse+1))
	if err != nil || len(b) > context1337MaxResponse {
		return errors.New("Context1337 response unreadable or too large")
	}
	if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' || json.Unmarshal(b, out) != nil {
		return errors.New("invalid Context1337 JSON response")
	}
	return nil
}

type context1337Health struct {
	Status string `json:"status"`
	Total *int `json:"total_resources"`
	Skills int `json:"skills"`
	Vulns int `json:"vulns"`
	Dicts int `json:"dicts"`
	Payloads int `json:"payloads"`
}

func (c *context1337Client) status(ctx context.Context) (any, error) {
	var h context1337Health
	if err := c.get(ctx, "/api/health", nil, &h); err != nil {
		return nil, err
	}
	if h.Status != "ok" || h.Total == nil || *h.Total < 0 || h.Skills < 0 ||
		h.Vulns < 0 || h.Dicts < 0 || h.Payloads < 0 {
		return nil, errors.New("invalid Context1337 health response")
	}
	return struct {
		Provider string `json:"provider"`
		Scope string `json:"scope"`
		context1337Health
	}{"context1337", "enabled resources visible to the configured key; counts only", h}, nil
}

type context1337Reference struct {
	CVE string `json:"cve"`
	Source string `json:"source"`
	ResourceID string `json:"resource_id"`
}

type context1337SearchResult struct {
	Provider string `json:"provider"`
	CVE string `json:"cve"`
	Source string `json:"source"`
	TargetVulnerability string `json:"target_vulnerability"`
	UpstreamTotal int `json:"upstream_candidate_total"`
	PageTruncated bool `json:"upstream_page_truncated"`
	Matches []context1337Reference `json:"matches"`
}

func (c *context1337Client) search(ctx context.Context, cve, source string) (context1337SearchResult, error) {
	result := context1337SearchResult{
		Provider: "context1337", CVE: cve, Source: source,
		TargetVulnerability: "unverified", Matches: []context1337Reference{},
	}
	if !context1337CVE.MatchString(cve) || (source != "builtin" && source != "nuclei") {
		return result, errors.New("one complete CVE ID and builtin or nuclei source required")
	}
	query := url.Values{
		"q": {cve}, "type": {"vuln"}, "enabled": {"true"},
		"source": {source}, "limit": {"20"}, "offset": {"0"},
	}
	var page struct {
		QueryApplied bool `json:"query_applied"`
		Total *int `json:"total"`
		Items *[]struct {
			Type string `json:"type"`
			Name string `json:"name"`
			Source string `json:"source"`
			Enabled bool `json:"enabled"`
		} `json:"items"`
	}
	if err := c.get(ctx, "/api/resources", query, &page); err != nil {
		return result, err
	}
	if !page.QueryApplied || page.Items == nil || page.Total == nil ||
		*page.Total < len(*page.Items) || len(*page.Items) > context1337PageLimit {
		return result, errors.New("invalid Context1337 search response")
	}
	result.UpstreamTotal = *page.Total
	result.PageTruncated = *page.Total > len(*page.Items)
	for _, item := range *page.Items {
		if item.Type != "vuln" || !item.Enabled || item.Source != source {
			return result, errors.New("Context1337 returned a resource outside requested filters")
		}
		if item.Name == cve && len(result.Matches) == 0 {
			result.Matches = append(result.Matches, context1337Reference{
				CVE: cve, Source: source,
				ResourceID: "absec://" + source + "/vuln/" + cve,
			})
		}
	}
	return result, nil
}

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
		(args[0] == "search" && (!context1337CVE.MatchString(*cve) || (*source != "builtin" && *source != "nuclei"))) {
		fmt.Fprintln(errOut, "context1337: invalid action arguments")
		return 2
	}
	client, err := newContext1337Client(getenv("ARTEX_CONTEXT1337_URL"), getenv("ARTEX_CONTEXT1337_API_KEY"))
	if err != nil {
		fmt.Fprintln(errOut, "context1337:", err)
		return 1
	}
	var result any
	if args[0] == "status" {
		result, err = client.status(ctx)
	} else {
		result, err = client.search(ctx, *cve, *source)
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
