package selfupdate

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
	"strings"
	"time"
)

// Repo 是发布源。写死而不是做成配置项：更新源可配等于给任何能改配置的人一条
// 远程代码执行通道，对一个渗透测试平台来说这个口子开不得。
const Repo = "knowlet/artex-ymh"

// latestURL 是 GitHub 的"最新正式版"接口。它会自动跳过 prerelease 和 draft。
const latestURL = "https://api.github.com/repos/" + Repo + "/releases/latest"

const repoAPIPrefix = "/repos/" + Repo

// allowedHosts 限定升级链路能访问的域名。配合下面的 checkRedirect，
// 任何一跳被重定向到名单外的主机都会直接失败——这是防止 DNS 污染 / 中间人
// 把二进制换掉的第一道闸门，第二道是 SHA256SUMS 比对。
var allowedHosts = map[string]bool{
	"api.github.com":                       true,
	"github.com":                           true,
	"objects.githubusercontent.com":        true, // release 资产实际落地的对象存储
	"release-assets.githubusercontent.com": true,
	"raw.githubusercontent.com":            true,
}

// Release 是 GitHub Release 里我们关心的字段。
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []Asset   `json:"assets"`
}

// Asset 是 Release 上挂的一个文件。
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// NewClient 构造一个只认 GitHub 域名的 HTTP 客户端。proxy 为空则直连。
//
// 刻意不复用默认 Transport：升级链路必须强制走 TLS 且校验证书，不能被别处
// 设置的 InsecureSkipVerify 之类影响到。
func NewClient(proxy string) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Minute, // 下载整包，不能按请求级超时卡死
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("重定向次数过多")
			}
			if err := checkURL(req.URL); err != nil {
				return err
			}
			// 元数据查询只允许 api.github.com/repos/knowlet/artex-ymh/...，禁止偏离 fork 路径。
			if strings.EqualFold(req.URL.Hostname(), "api.github.com") {
				if err := checkRepoAPIPath(req.URL); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// checkURL 强制 https + 域名白名单。
func checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("拒绝非 HTTPS 地址: %s", u.Scheme+"://"+u.Host)
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] {
		return fmt.Errorf("拒绝非 GitHub 域名: %s", u.Hostname())
	}
	return nil
}

func checkRepoAPIPath(u *url.URL) error {
	lower := strings.ToLower(u.Path)
	prefix := strings.ToLower(repoAPIPrefix)
	if lower != prefix && !strings.HasPrefix(lower, prefix+"/") {
		return fmt.Errorf("拒绝非 fork 仓库路径: %s", u.Path)
	}
	return nil
}

func verifyMetadataResponseURL(resp *http.Response) error {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return checkError("github_error", "更新源响应 URL 无法确认")
	}
	u := resp.Request.URL
	if !strings.EqualFold(u.Hostname(), "api.github.com") {
		return checkError("github_error", "更新源响应不在 api.github.com")
	}
	if err := checkRepoAPIPath(u); err != nil {
		return checkError("github_error", "更新源响应来自非 fork 仓库，已拒绝")
	}
	return nil
}

const maxGitHubMetadataBytes = 1 << 20 // 1 MiB — release/repo JSON is tiny

func releaseBelongsToFork(rel Release) bool {
	if rel.HTMLURL == "" {
		return true
	}
	u, err := url.Parse(rel.HTMLURL)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") {
		return false
	}
	wantPrefix := "/" + Repo + "/"
	lowerPath := strings.ToLower(u.Path)
	return strings.HasPrefix(lowerPath, strings.ToLower(wantPrefix))
}

// CheckError identifies a release-check failure without treating every failure as
// a network/proxy problem. The wrapped error preserves cancellation detection.
type CheckError struct {
	Code string
	Err  error
}

func (e *CheckError) Error() string { return e.Err.Error() }
func (e *CheckError) Unwrap() error { return e.Err }

// CheckErrorCode is stable across error wrapping and is sent to the settings UI.
func CheckErrorCode(err error) string {
	var e *CheckError
	if errors.As(err, &e) {
		return e.Code
	}
	return "unknown"
}

func checkError(code, message string) error {
	return &CheckError{Code: code, Err: errors.New(message)}
}

func classifyDoError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &CheckError{Code: "unknown", Err: fmt.Errorf("检查更新已取消或超时: %w", err)}
	}
	msg := err.Error()
	if strings.Contains(msg, "拒绝非") || strings.Contains(msg, "重定向次数过多") {
		return &CheckError{Code: "github_error", Err: fmt.Errorf("更新源校验失败: %w", err)}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return &CheckError{Code: "network", Err: fmt.Errorf("访问 GitHub 失败: %w", err)}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return &CheckError{Code: "network", Err: fmt.Errorf("访问 GitHub 失败: %w", err)}
	}
	return &CheckError{Code: "github_error", Err: fmt.Errorf("访问 GitHub 失败: %w", err)}
}

func decodeSingleJSON(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("响应含有多余数据")
		}
		return err
	}
	return nil
}

func githubRequest(ctx context.Context, c *http.Client, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, classifyDoError(err)
	}
	if strings.EqualFold(req.URL.Hostname(), "api.github.com") {
		if err := checkRepoAPIPath(req.URL); err != nil {
			return nil, classifyDoError(err)
		}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "artex-selfupdate")
	resp, err := c.Do(req)
	if err != nil {
		return nil, classifyDoError(err)
	}
	if err := verifyMetadataResponseURL(resp); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

func readGitHubResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxGitHubMetadataBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxGitHubMetadataBytes {
		return nil, errors.New("GitHub 响应过大")
	}
	return body, nil
}

func githubStatusError(status int, header http.Header, body []byte) error {
	msg := strings.ToLower(string(body))
	switch {
	case status == http.StatusTooManyRequests:
		return checkError("rate_limited", "GitHub 接口限流，请稍后再试")
	case status == http.StatusForbidden &&
		(header.Get("X-RateLimit-Remaining") == "0" ||
			header.Get("Retry-After") != "" ||
			strings.Contains(msg, "secondary rate limit") ||
			strings.Contains(msg, "abuse detection")):
		return checkError("rate_limited", "GitHub 接口限流，请稍后再试")
	case status == http.StatusForbidden, status == http.StatusUnauthorized:
		return checkError("access_denied", "GitHub 拒绝访问更新源，请检查仓库可见性或访问权限")
	case status != http.StatusOK:
		return checkError("github_error", fmt.Sprintf("GitHub 返回 %d，无法确认最新版本", status))
	}
	return nil
}

func decodeRepoInfo(body io.Reader) (fullName string, err error) {
	var info struct {
		FullName string `json:"full_name"`
	}
	if err := decodeSingleJSON(body, &info); err != nil {
		return "", err
	}
	return info.FullName, nil
}

// FetchLatest queries only this fork. A missing latest Release is ambiguous on
// GitHub: verify repository visibility before claiming that no release exists.
func FetchLatest(ctx context.Context, c *http.Client) (*Release, error) {
	resp, err := githubRequest(ctx, c, latestURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		repo, err := githubRequest(ctx, c, "https://api.github.com/repos/"+Repo)
		if err != nil {
			return nil, err
		}
		if repo.StatusCode == http.StatusNotFound {
			_ = repo.Body.Close()
			return nil, checkError("repository_unavailable", fmt.Sprintf("更新源 %s 不存在或当前不可见，无法确认是否有正式版本", Repo))
		}
		repoBody, err := readGitHubResponseBody(repo)
		if err != nil {
			return nil, &CheckError{Code: "github_error", Err: fmt.Errorf("读取 GitHub 响应失败: %w", err)}
		}
		if err := githubStatusError(repo.StatusCode, repo.Header, repoBody); err != nil {
			return nil, err
		}
		fullName, err := decodeRepoInfo(bytes.NewReader(repoBody))
		if err != nil || !strings.EqualFold(fullName, Repo) {
			return nil, checkError("github_error", "GitHub 返回的仓库信息无法确认更新源，不能判定为无正式版本")
		}
		return nil, checkError("no_release", fmt.Sprintf("仓库 %s 当前可访问，但没有可用的最新正式版本（不含预发布或草稿）", Repo))
	}
	releaseBody, err := readGitHubResponseBody(resp)
	if err != nil {
		return nil, &CheckError{Code: "github_error", Err: fmt.Errorf("读取 GitHub 响应失败: %w", err)}
	}
	if err := githubStatusError(resp.StatusCode, resp.Header, releaseBody); err != nil {
		return nil, err
	}
	var rel Release
	if err := decodeSingleJSON(bytes.NewReader(releaseBody), &rel); err != nil {
		return nil, &CheckError{Code: "invalid_release", Err: fmt.Errorf("解析 Release 失败: %w", err)}
	}
	if strings.TrimSpace(rel.TagName) == "" || rel.Draft || rel.Prerelease {
		return nil, checkError("invalid_release", "GitHub 未返回有效的最新正式版本")
	}
	if !releaseBelongsToFork(rel) {
		return nil, checkError("github_error", "GitHub 返回的 Release 不属于此 fork，已拒绝")
	}
	return &rel, nil
}

// AssetName 返回当前平台对应的发布包名，与 build.sh 的 package_binary 保持一致：
// artex-<版本>-<os>-<arch>.zip（版本号不带 v 前缀）。
func AssetName(tag, goos, goarch string) string {
	return fmt.Sprintf("artex-%s-%s-%s.zip", strings.TrimPrefix(tag, "v"), goos, goarch)
}

// FindAsset 在 Release 里按名字找资产。
func (r *Release) FindAsset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Asset{}, false
}
