package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type checkTransport func(*http.Request) (*http.Response, error)

func (f checkTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchLatestFailureClassification(t *testing.T) {
	cases := []struct {
		name     string
		statuses []int
		bodies   []string
		headers  http.Header
		want     string
	}{
		{"no release", []int{404, 200}, []string{"", `{"full_name":"knowlet/artex-ymh"}`}, nil, "no_release"},
		{"invisible repo", []int{404, 404}, nil, nil, "repository_unavailable"},
		{"repo permission", []int{404, 403}, nil, nil, "access_denied"},
		{"unauthorized", []int{401}, nil, nil, "access_denied"},
		{"forbidden is not necessarily a limit", []int{403}, nil, nil, "access_denied"},
		{"limit", []int{403}, nil, http.Header{"X-Ratelimit-Remaining": {"0"}}, "rate_limited"},
		{"secondary limit", []int{403}, nil, http.Header{"Retry-After": {"60"}}, "rate_limited"},
		{"too many requests", []int{429}, nil, nil, "rate_limited"},
		{"repo server failure", []int{404, 503}, nil, nil, "github_error"},
		{"server failure", []int{500}, nil, nil, "github_error"},
		{"invalid repo response", []int{404, 200}, []string{"", `<html>not metadata</html>`}, nil, "github_error"},
		{"redirected repo identity", []int{404, 200}, []string{"", `{"full_name":"Autumn-27/artex"}`}, nil, "github_error"},
		{"invalid release JSON", []int{200}, []string{`<html>`}, nil, "invalid_release"},
		{"missing tag", []int{200}, []string{`{}`}, nil, "invalid_release"},
		{"draft", []int{200}, []string{`{"tag_name":"v0.3.13","draft":true}`}, nil, "invalid_release"},
		{"prerelease", []int{200}, []string{`{"tag_name":"v0.3.13","prerelease":true}`}, nil, "invalid_release"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := &http.Client{Transport: checkTransport(func(r *http.Request) (*http.Response, error) {
				if calls >= len(tc.statuses) {
					t.Fatal("unexpected extra request")
				}
				wantURL := latestURL
				if calls == 1 {
					wantURL = "https://api.github.com/repos/" + Repo
				}
				if r.URL.String() != wantURL || r.Method != http.MethodGet {
					t.Fatalf("unexpected request %s %s", r.Method, r.URL)
				}
				if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") != "artex-selfupdate" {
					t.Fatal("missing API headers")
				}
				body := ""
				if calls < len(tc.bodies) {
					body = tc.bodies[calls]
				}
				status := tc.statuses[calls]
				calls++
				return &http.Response{StatusCode: status, Header: tc.headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			rel, err := FetchLatest(t.Context(), c)
			if err == nil || rel != nil || CheckErrorCode(fmt.Errorf("wrapped: %w", err)) != tc.want {
				t.Fatalf("release=%+v error=%v code=%s want=%s", rel, err, CheckErrorCode(err), tc.want)
			}
			if calls != len(tc.statuses) {
				t.Fatalf("calls=%d want=%d", calls, len(tc.statuses))
			}
		})
	}
}

func TestFetchLatestNetworkAndCancellation(t *testing.T) {
	for _, networkErr := range []error{errors.New("connection failed"), context.Canceled} {
		c := &http.Client{Transport: checkTransport(func(*http.Request) (*http.Response, error) { return nil, networkErr })}
		_, err := FetchLatest(t.Context(), c)
		if CheckErrorCode(err) != "network" || !errors.Is(err, networkErr) {
			t.Fatalf("network error lost classification/cause: %v", err)
		}
	}
}

func TestFetchLatestUsesOnlyFork(t *testing.T) {
	if Repo != "knowlet/artex-ymh" {
		t.Fatalf("unsafe update source: %s", Repo)
	}
	calls := 0
	c := &http.Client{Transport: checkTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.github.com/repos/knowlet/artex-ymh/releases/latest" {
			t.Fatalf("unexpected update source %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v0.3.13"}`)), Request: r}, nil
	})}
	rel, err := FetchLatest(t.Context(), c)
	if err != nil || rel == nil || rel.TagName != "v0.3.13" || calls != 1 {
		t.Fatalf("rel=%+v err=%v calls=%d", rel, err, calls)
	}
}

func TestStageDisabledBeforeAnySideEffects(t *testing.T) {
	t.Setenv(skipSignEnv, "1")
	if InstallEnabled {
		t.Fatal("fork release chain has not been reviewed")
	}
	// nil client/release would panic if download or filesystem setup were reached.
	err := Stage(t.Context(), nil, nil, "0.3.12", func(Phase, int, string) { t.Fatal("disabled install published progress") })
	if !errors.Is(err, ErrInstallDisabled) {
		t.Fatalf("want disabled error, got %v", err)
	}
}
