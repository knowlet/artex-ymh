package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/context1337"
)

func context1337Env(endpoint string) func(string) string {
	return func(k string) string {
		switch k {
		case "ARTEX_CONTEXT1337_URL":
			return endpoint
		case "ARTEX_CONTEXT1337_API_KEY":
			return "test-secret"
		}
		return ""
	}
}

func TestContext1337Status(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/health" || r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("unexpected request")
		}
		fmt.Fprint(w, `{"status":"ok","total_resources":3,"vulns":2,"skills":1,"body":"never output this"}`)
	}))
	defer server.Close()
	var out, errs bytes.Buffer
	if code := runContext1337(context.Background(), []string{"status"}, context1337Env(server.URL), &out, &errs); code != 0 {
		t.Fatalf("code=%d %s", code, &errs)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got["total_resources"] != float64(3) || got["provider"] != "context1337" || strings.Contains(out.String(), "never output") {
		t.Fatalf("unexpected result: %s", &out)
	}
}

func TestContext1337ExactMetadataOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.Method != "GET" || r.URL.Path != "/api/resources" || q.Get("q") != "CVE-2999-1234" ||
			q.Get("type") != "vuln" || q.Get("enabled") != "true" || q.Get("source") != "nuclei" ||
			q.Get("limit") != "20" || r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("unexpected request")
		}
		fmt.Fprint(w, `{"query_applied":true,"total":3,"items":[{"type":"vuln","name":"CVE-2999-1234","source":"nuclei","enabled":true,"body":"untrusted body","description":"untrusted description"},{"type":"vuln","name":"CVE-2999-9999","source":"nuclei","enabled":true}]}`)
	}))
	defer server.Close()
	var out, errs bytes.Buffer
	if code := runContext1337(context.Background(), []string{"search", "--cve", "CVE-2999-1234", "--source", "nuclei"}, context1337Env(server.URL), &out, &errs); code != 0 {
		t.Fatalf("code=%d %s", code, &errs)
	}
	var got context1337.SearchResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got.Matches) != 1 ||
		got.Matches[0].ResourceID != "absec://nuclei/vuln/CVE-2999-1234" ||
		got.TargetVulnerability != "unverified" || !got.PageTruncated || strings.Contains(out.String(), "untrusted") {
		t.Fatalf("unexpected result: %s", &out)
	}
}

func TestContext1337RejectConfig(t *testing.T) {
	for _, endpoint := range []string{"", "http://example.com", "http://localhost:1337", "https://user:secret@example.com", "https://example.com/path", "https://example.com?token=secret"} {
		if _, err := context1337.NewClient(endpoint, "key"); err == nil {
			t.Errorf("accepted invalid origin %q", endpoint)
		}
	}
	for _, key := range []string{"", "a b", "a\nB"} {
		if _, err := context1337.NewClient("https://example.com", key); err == nil {
			t.Error("accepted invalid key")
		}
	}
	for _, args := range [][]string{nil, {"run"}, {"status", "--source", "builtin"}, {"search"}, {"search", "--cve", "arbitrary"}, {"search", "--cve", "CVE-2999-1234", "--source", "team"}} {
		var out, errs bytes.Buffer
		if code := runContext1337(context.Background(), args, context1337Env(""), &out, &errs); code != 2 || out.Len() != 0 {
			t.Errorf("invalid invocation accepted: %v", args)
		}
	}
}

func TestContext1337HTTPFailuresAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"auth", 401, "test-secret"},
		{"unavailable", 503, "test-secret"},
		{"oversize", 200, strings.Repeat("x", context1337.MaxResponse+1)},
		{"bad-json", 200, "test-secret"},
		{"invalid-health", 200, `{"status":"ok"}`},
		{"trailing-json", 200, `{"status":"ok","total_resources":0}{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			var out, errs bytes.Buffer
			if code := runContext1337(context.Background(), []string{"status"}, context1337Env(server.URL), &out, &errs); code != 1 || out.Len() != 0 || strings.Contains(errs.String(), "test-secret") {
				t.Fatalf("failure leaked or accepted: %d %s %s", code, &out, &errs)
			}
		})
	}
}

func TestContext1337NoRedirect(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect followed")
	}))
	defer dest.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusFound)
	}))
	defer server.Close()
	var out, errs bytes.Buffer
	if code := runContext1337(context.Background(), []string{"status"}, context1337Env(server.URL), &out, &errs); code != 1 || out.Len() != 0 {
		t.Fatal("redirect accepted")
	}
}

func TestContext1337RejectWrongResource(t *testing.T) {
	for _, item := range []string{
		`{"type":"dict","name":"CVE-2999-1234","source":"builtin","enabled":true}`,
		`{"type":"vuln","name":"CVE-2999-1234","source":"team","enabled":true}`,
		`{"type":"vuln","name":"CVE-2999-1234","source":"builtin","enabled":false}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"query_applied":true,"total":1,"items":[%s]}`, item)
		}))
		var out, errs bytes.Buffer
		code := runContext1337(context.Background(), []string{"search", "--cve", "CVE-2999-1234"}, context1337Env(server.URL), &out, &errs)
		server.Close()
		if code != 1 || out.Len() != 0 {
			t.Fatal("out of scope resource accepted")
		}
	}
}

func TestContext1337Cancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errs bytes.Buffer
	if code := runContext1337(ctx, []string{"status"}, context1337Env(server.URL), &out, &errs); code != 1 || out.Len() != 0 {
		t.Fatal("cancelled request accepted")
	}
}
