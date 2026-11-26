// Package context1337 provides a bounded, metadata-only client for an operator-owned service.
package context1337

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	// MaxResponse bounds the entire upstream JSON response, including ignored fields.
	MaxResponse = 512 << 10
	// PageLimit bounds the single upstream search page; the client never follows pages.
	PageLimit = 20
)

var validCVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// ValidCVE accepts only a complete, canonical CVE identifier.
func ValidCVE(value string) bool { return validCVE.MatchString(value) }

// Client queries one fixed operator-owned origin without task proxies or redirects.
// It is safe for concurrent calls; exercise authorization belongs to the caller.
type Client struct {
	endpoint *url.URL
	key      string
	http     *http.Client
}

// unambiguousJSON rejects duplicate keys, including spellings that encoding/json
// would match case-insensitively. Otherwise a later key could replace an earlier
// filter value before the metadata projection is checked.
func unambiguousJSON(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return true
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				token, err := decoder.Token()
				key, ok := token.(string)
				if err != nil || !ok {
					return false
				}
				folded := strings.Map(func(r rune) rune {
					least := r
					for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
						if next < least {
							least = next
						}
					}
					return least
				}, key)
				if _, exists := seen[folded]; exists {
					return false
				}
				seen[folded] = struct{}{}
				if !value(depth + 1) {
					return false
				}
			}
		case '[':
			for decoder.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		end, err := decoder.Token()
		return err == nil && ((delim == '{' && end == json.Delim('}')) || (delim == '[' && end == json.Delim(']')))
	}
	if !value(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

// NewClient validates operator-owned configuration and uses no default endpoint.
// It never reuses a task HTTP proxy or accepts an agent-selected destination.
func NewClient(endpoint, key string) (*Client, error) {
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
		DialContext:            (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 32 << 10,
	}
	return &Client{
		endpoint: u, key: key,
		http: &http.Client{
			Transport: transport, Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Only fixed GET routes are used. Error output never includes remote bodies,
// endpoint URLs, request headers, or credentials.
func (c *Client) get(ctx context.Context, route string, query url.Values, out any) error {
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
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || len(b) > MaxResponse {
		return errors.New("Context1337 response unreadable or too large")
	}
	if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' || !unambiguousJSON(b) || json.Unmarshal(b, out) != nil {
		return errors.New("invalid Context1337 JSON response")
	}
	return nil
}

type health struct {
	Status   string `json:"status"`
	Total    *int   `json:"total_resources"`
	Skills   int    `json:"skills"`
	Vulns    int    `json:"vulns"`
	Dicts    int    `json:"dicts"`
	Payloads int    `json:"payloads"`
}

// Status returns validated resource counts, without remote text or content.
func (c *Client) Status(ctx context.Context) (any, error) {
	var h health
	if err := c.get(ctx, "/api/health", nil, &h); err != nil {
		return nil, err
	}
	if h.Status != "ok" || h.Total == nil || *h.Total < 0 || h.Skills < 0 ||
		h.Vulns < 0 || h.Dicts < 0 || h.Payloads < 0 {
		return nil, errors.New("invalid Context1337 health response")
	}
	return struct {
		Provider string `json:"provider"`
		Scope    string `json:"scope"`
		health
	}{"context1337", "enabled resources visible to the configured key; counts only", h}, nil
}

// Reference identifies an exact CVE metadata match, not evidence about a target.
type Reference struct {
	CVE        string `json:"cve"`
	Source     string `json:"source"`
	ResourceID string `json:"resource_id"`
}

// SearchResult contains only fixed labels, counts and locally constructed references.
type SearchResult struct {
	Provider            string      `json:"provider"`
	CVE                 string      `json:"cve"`
	Source              string      `json:"source"`
	TargetVulnerability string      `json:"target_vulnerability"`
	UpstreamTotal       int         `json:"upstream_candidate_total"`
	PageTruncated       bool        `json:"upstream_page_truncated"`
	Matches             []Reference `json:"matches"`
}

// Search queries one bounded first page and projects exact enabled CVE matches.
// A missing match does not establish absence from the corpus or safety of a target.
func (c *Client) Search(ctx context.Context, cve, source string) (SearchResult, error) {
	result := SearchResult{
		Provider: "context1337", CVE: cve, Source: source,
		TargetVulnerability: "unverified", Matches: []Reference{},
	}
	if !ValidCVE(cve) || (source != "builtin" && source != "nuclei") {
		return result, errors.New("one complete CVE ID and builtin or nuclei source required")
	}
	query := url.Values{
		"q": {cve}, "type": {"vuln"}, "enabled": {"true"},
		"source": {source}, "limit": {strconv.Itoa(PageLimit)}, "offset": {"0"},
	}
	var page struct {
		QueryApplied bool `json:"query_applied"`
		Total        *int `json:"total"`
		Items        *[]struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Source  string `json:"source"`
			Enabled bool   `json:"enabled"`
		} `json:"items"`
	}
	if err := c.get(ctx, "/api/resources", query, &page); err != nil {
		return result, err
	}
	if !page.QueryApplied || page.Items == nil || page.Total == nil ||
		*page.Total < len(*page.Items) || len(*page.Items) > PageLimit {
		return result, errors.New("invalid Context1337 search response")
	}
	result.UpstreamTotal = *page.Total
	result.PageTruncated = *page.Total > len(*page.Items)
	for _, item := range *page.Items {
		if item.Type != "vuln" || !item.Enabled || item.Source != source {
			result.Matches = []Reference{}
			return result, errors.New("Context1337 returned a resource outside requested filters")
		}
		if item.Name == cve && len(result.Matches) == 0 {
			result.Matches = append(result.Matches, Reference{
				CVE: cve, Source: source,
				ResourceID: "absec://" + source + "/vuln/" + cve,
			})
		}
	}
	return result, nil
}
