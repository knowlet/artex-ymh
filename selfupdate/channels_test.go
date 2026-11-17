package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

const channelTestSHA = "0123456789abcdef0123456789abcdef01234567"

func channelCommitJSON(sha string) string {
	return fmt.Sprintf(`{"sha":%q,"html_url":"https://github.com/knowlet/artex-ymh/commit/%s","commit":{"message":"main change","committer":{"date":"2026-11-17T00:00:00Z"}}}`, sha, sha)
}

func TestFetchChannelMainWithoutRelease(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: checkTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.github.com/repos/"+Repo+"/commits/main" {
			t.Fatalf("main must not depend on a Release: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(channelCommitJSON(channelTestSHA))), Request: r}, nil
	})}
	rel, err := FetchChannel(t.Context(), client, ChannelMain)
	if err != nil || rel == nil {
		t.Fatalf("rel=%+v err=%v", rel, err)
	}
	if calls != 1 || rel.CommitSHA != channelTestSHA || rel.TagName != "main@0123456789ab" || len(rel.Assets) != 0 || rel.Body != "main change" {
		t.Fatalf("unexpected main metadata: %+v (calls=%d)", rel, calls)
	}
}

func TestFetchChannelNightlyPublicationOrderAndMovingTag(t *testing.T) {
	sha := channelTestSHA
	client := &http.Client{Transport: checkTransport(func(r *http.Request) (*http.Response, error) {
		body := `[
			{"tag_name":"v9.0.0","published_at":"2026-11-19T00:00:00Z"},
			{"tag_name":"draft","draft":true,"prerelease":true,"published_at":"2026-11-20T00:00:00Z"},
			{"tag_name":"v1.0.0-rc1","prerelease":true,"published_at":"2026-11-15T00:00:00Z"},
			{"tag_name":"nightly","published_at":"2026-11-17T00:00:00Z"}
		]`
		switch r.URL.RequestURI() {
		case repoAPIPrefix + "/releases?per_page=100&page=1":
		case repoAPIPrefix + "/commits/nightly":
			body = channelCommitJSON(sha)
		default:
			t.Fatalf("unexpected source: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	for _, next := range []string{channelTestSHA, strings.Repeat("a", 40)} {
		sha = next
		rel, err := FetchChannel(t.Context(), client, ChannelNightly)
		if err != nil || rel == nil || rel.TagName != "nightly" || rel.CommitSHA != next || rel.Draft {
			t.Fatalf("nightly rel=%+v err=%v", rel, err)
		}
	}
}

func TestFetchChannelNightlyPaginates(t *testing.T) {
	page := make([]Release, 100)
	for i := range page {
		page[i].TagName = "v1.0.0"
	}
	first, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client := &http.Client{Transport: checkTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var body string
		switch r.URL.RequestURI() {
		case repoAPIPrefix + "/releases?per_page=100&page=1":
			body = string(first)
		case repoAPIPrefix + "/releases?per_page=100&page=2":
			body = `[{"tag_name":"v2.0.0-beta","prerelease":true,"published_at":"2026-11-16T00:00:00Z"}]`
		case repoAPIPrefix + "/commits/v2.0.0-beta":
			body = channelCommitJSON(channelTestSHA)
		default:
			t.Fatalf("unexpected page: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	rel, err := FetchChannel(t.Context(), client, ChannelNightly)
	if err != nil || rel == nil || rel.TagName != "v2.0.0-beta" || calls != 3 {
		t.Fatalf("rel=%+v err=%v calls=%d", rel, err, calls)
	}
}

func TestFetchChannelRejectsInvalidMetadata(t *testing.T) {
	cases := []struct {
		name    string
		channel Channel
		body    string
		status  int
		code    string
	}{
		{"main missing", ChannelMain, `{}`, 404, "ref_unavailable"},
		{"main short SHA", ChannelMain, channelCommitJSON("abc1234"), 200, "invalid_release"},
		{"main invalid SHA", ChannelMain, channelCommitJSON(strings.Repeat("z", 40)), 200, "invalid_release"},
		{"main other fork", ChannelMain, strings.ReplaceAll(channelCommitJSON(channelTestSHA), Repo, "Autumn-27/artex"), 200, "github_error"},
		{"main extra JSON", ChannelMain, channelCommitJSON(channelTestSHA) + ` {}`, 200, "invalid_release"},
		{"nightly empty", ChannelNightly, `[]`, 200, "no_release"},
		{"nightly only drafts", ChannelNightly, `[{"tag_name":"nightly","draft":true}]`, 200, "no_release"},
		{"nightly only stable", ChannelNightly, `[{"tag_name":"v1.0.0"}]`, 200, "no_release"},
		{"nightly null", ChannelNightly, `null`, 200, "invalid_release"},
		{"nightly missing publication", ChannelNightly, `[{"tag_name":"nightly"}]`, 200, "invalid_release"},
		{"nightly other fork", ChannelNightly, `[{"tag_name":"nightly","published_at":"2026-11-17T00:00:00Z","html_url":"https://github.com/Autumn-27/artex/releases/tag/nightly"}]`, 200, "github_error"},
		{"nightly missing repo", ChannelNightly, `{}`, 404, "repository_unavailable"},
		{"nightly rate limit", ChannelNightly, `{}`, 429, "rate_limited"},
		{"main forbidden", ChannelMain, `{}`, 403, "access_denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: checkTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})}
			rel, err := FetchChannel(t.Context(), client, tc.channel)
			if err == nil || rel != nil || CheckErrorCode(err) != tc.code {
				t.Fatalf("rel=%+v err=%v code=%s want=%s", rel, err, CheckErrorCode(err), tc.code)
			}
		})
	}
}

func TestFetchChannelNightlyBoundsPagination(t *testing.T) {
	page := make([]Release, 100)
	body, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client := &http.Client{Transport: checkTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})}
	_, err = FetchChannel(t.Context(), client, ChannelNightly)
	if CheckErrorCode(err) != "github_error" || calls != 5 {
		t.Fatalf("incomplete search misreported: %v, calls=%d", err, calls)
	}
}

func TestFetchChannelRejectsUnknownChannelBeforeRequest(t *testing.T) {
	if channel, err := ParseChannel(""); err != nil || channel != ChannelStable {
		t.Fatalf("default: %q %v", channel, err)
	}
	for _, raw := range []string{"dev", "MAIN", "../main", "https://example.com", "stable "} {
		if _, err := ParseChannel(raw); CheckErrorCode(err) != "invalid_channel" {
			t.Fatalf("accepted channel %q", raw)
		}
		if _, err := FetchChannel(context.Background(), nil, Channel(raw)); CheckErrorCode(err) != "invalid_channel" {
			t.Fatalf("fetch accepted channel %q", raw)
		}
	}
}
