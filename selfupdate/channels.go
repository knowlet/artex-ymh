package selfupdate

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Channel changes metadata selection, never the trusted repository or install policy.
type Channel string

const (
	ChannelStable  Channel = "stable"
	ChannelNightly Channel = "nightly"
	ChannelMain    Channel = "main"
)

func ParseChannel(raw string) (Channel, error) {
	switch Channel(raw) {
	case "", ChannelStable:
		return ChannelStable, nil
	case ChannelNightly:
		return ChannelNightly, nil
	case ChannelMain:
		return ChannelMain, nil
	default:
		return "", checkError("invalid_channel", "更新通道仅支持 stable、nightly 或 main")
	}
}

// FetchChannel preserves FetchLatest's stable-only contract for existing callers.
func FetchChannel(ctx context.Context, c *http.Client, channel Channel) (*Release, error) {
	switch channel {
	case ChannelStable:
		return FetchLatest(ctx, c)
	case ChannelNightly:
		return fetchNightly(ctx, c)
	case ChannelMain:
		return fetchCommit(ctx, c, "main")
	default:
		return nil, checkError("invalid_channel", "无效更新通道")
	}
}

func fetchNightly(ctx context.Context, c *http.Client) (*Release, error) {
	// Bound API quota as well as individual response size. A full final page is
	// an incomplete search, not evidence that no nightly exists.
	const pageSize, maxPages = 100, 5
	var latest *Release
	for page := 1; page <= maxPages; page++ {
		endpoint := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=%d&page=%d", Repo, pageSize, page)
		resp, err := githubRequest(ctx, c, endpoint)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound {
			_ = resp.Body.Close()
			return nil, checkError("repository_unavailable", "更新源不存在或当前不可见，无法查询 nightly")
		}
		body, err := readGitHubResponseBody(resp)
		if err != nil {
			return nil, &CheckError{Code: "github_error", Err: err}
		}
		if err := githubStatusError(resp.StatusCode, resp.Header, body); err != nil {
			return nil, err
		}
		var releases []Release
		if err := decodeSingleJSON(bytes.NewReader(body), &releases); err != nil || releases == nil {
			return nil, checkError("invalid_release", "GitHub 未返回有效的 Release 列表")
		}
		for _, rel := range releases {
			tag := strings.ToLower(rel.TagName)
			if rel.Draft || !(rel.Prerelease || tag == "nightly" || strings.HasPrefix(tag, "nightly-")) {
				continue
			}
			if strings.TrimSpace(rel.TagName) == "" || rel.PublishedAt.IsZero() {
				return nil, checkError("invalid_release", "nightly 缺少标签或发布时间")
			}
			if !releaseBelongsToFork(rel) {
				return nil, checkError("github_error", "nightly 不属于此 fork，已拒绝")
			}
			if latest == nil || rel.PublishedAt.After(latest.PublishedAt) {
				copy := rel
				latest = &copy
			}
		}
		if len(releases) < pageSize {
			if latest == nil {
				return nil, checkError("no_release", "仓库当前可访问，但尚未发布 nightly 或预发布版本；可选择 main 最新提交")
			}
			commit, err := fetchCommit(ctx, c, latest.TagName)
			if err != nil {
				return nil, err
			}
			latest.CommitSHA = commit.CommitSHA
			return latest, nil
		}
	}
	return nil, checkError("github_error", "Release 列表超出查询上限，无法确认最新 nightly")
}

// ValidCommitSHA accepts only a full SHA-1 object ID; never interpolate metadata
// or a user-supplied branch into a source URL or a version identity.
func ValidCommitSHA(sha string) bool {
	if len(sha) != 40 {
		return false
	}
	_, err := hex.DecodeString(sha)
	return err == nil
}

func fetchCommit(ctx context.Context, c *http.Client, ref string) (*Release, error) {
	resp, err := githubRequest(ctx, c, "https://api.github.com/repos/"+Repo+"/commits/"+url.PathEscape(ref))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return nil, checkError("ref_unavailable", "更新源的提交或引用不存在，或仓库当前不可见")
	}
	body, err := readGitHubResponseBody(resp)
	if err != nil {
		return nil, &CheckError{Code: "github_error", Err: err}
	}
	if err := githubStatusError(resp.StatusCode, resp.Header, body); err != nil {
		return nil, err
	}
	var commit struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message   string `json:"message"`
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := decodeSingleJSON(bytes.NewReader(body), &commit); err != nil || !ValidCommitSHA(commit.SHA) {
		return nil, checkError("invalid_release", "GitHub 未返回有效的完整提交 SHA")
	}
	sha := strings.ToLower(commit.SHA)
	wantURL := "https://github.com/" + Repo + "/commit/" + sha
	if commit.HTMLURL != "" && !strings.EqualFold(commit.HTMLURL, wantURL) {
		return nil, checkError("github_error", "GitHub 返回的提交不属于此 fork，已拒绝")
	}
	return &Release{
		TagName:     ref + "@" + sha[:12],
		Body:        commit.Commit.Message,
		PublishedAt: commit.Commit.Committer.Date,
		HTMLURL:     wantURL,
		CommitSHA:   sha,
	}, nil
}
