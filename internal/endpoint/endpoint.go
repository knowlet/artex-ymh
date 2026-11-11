// Package endpoint binds stored credentials to their configured destination.
// Local and private endpoints remain valid operator choices.
package endpoint

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var ErrCredentialDestination = errors.New("目标地址、提供商或代理已更改，请重新填写凭据")

type LLMDestination struct {
	Provider string
	BaseURL  string
	Proxy    string
}

// LLM applies the same endpoint suffixes and defaults as the provider. Resolve
// norma's environment defaults here as well, so comparison and delivery agree.
func LLM(provider, baseURL, proxy string) (LLMDestination, error) {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		provider = "anthropic"
	}
	var suffix, envKey, fallback string
	switch provider {
	case "openai":
		suffix, envKey, fallback = "/chat/completions", "OPENAI_BASE_URL", "https://api.openai.com/v1"
	case "openai-responses":
		suffix, envKey, fallback = "/responses", "OPENAI_BASE_URL", "https://api.openai.com/v1"
	case "anthropic":
		suffix, envKey, fallback = "/v1/messages", "ANTHROPIC_BASE_URL", "https://api.anthropic.com"
	default:
		return LLMDestination{}, errors.New("不支持的 LLM 提供商")
	}
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv(envKey))
		if baseURL == "" {
			baseURL = fallback
		}
	}
	u, err := parseURL(baseURL, false)
	if err != nil {
		return LLMDestination{}, err
	}
	escaped := strings.TrimRight(strings.TrimSuffix(strings.TrimRight(u.EscapedPath(), "/"), suffix), "/")
	u.Path, _ = url.PathUnescape(escaped)
	u.RawPath = escaped // preserve escaped separators in enterprise routing paths
	p := ""
	if strings.TrimSpace(proxy) != "" {
		pu, err := parseURL(proxy, true)
		if err != nil {
			return LLMDestination{}, err
		}
		p = pu.String()
	}
	return LLMDestination{Provider: provider, BaseURL: u.String(), Proxy: p}, nil
}

// URL compares a complete HTTP endpoint, including path and query. It does not
// impose a public-network allowlist: enterprise MCP servers commonly run locally.
func URL(raw string) (string, error) {
	u, err := parseURL(raw, false)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// ValidateAssetURL checks that a service URL is safe to persist and later
// render as a clickable http(s) link. It does not rewrite the URL string, so
// storage keys and operator-entered spelling stay stable (fragments and paths
// are preserved; only scheme/host sanity is enforced).
func ValidateAssetURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("url is required")
	}
	// Mirror web safeHref: strip ASCII control/space before scheme detection.
	var b strings.Builder
	for _, r := range raw {
		if r > ' ' {
			b.WriteRune(r)
		}
	}
	cleaned := b.String()
	if cleaned == "" {
		return errors.New("资产 URL 无效")
	}
	u, err := url.Parse(cleaned)
	if err != nil || u == nil || u.Opaque != "" || u.Hostname() == "" {
		return errors.New("资产 URL 无效")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("资产 URL 仅支持 HTTP 或 HTTPS")
	}
	return nil
}

func parseURL(raw string, proxy bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Hostname() == "" || u.Opaque != "" || u.Fragment != "" {
		return nil, errors.New("目标地址必须是有效的完整 URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" && !(proxy && u.Scheme == "socks5") {
		return nil, errors.New("目标地址仅支持 HTTP(S)，代理另支持 SOCKS5")
	}
	if !proxy && u.User != nil {
		return nil, errors.New("请通过凭据字段配置认证，不要在目标 URL 中嵌入凭据")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	if u.Path == "/" {
		u.Path = ""
		u.RawPath = ""
	}
	return u, nil
}

// CheckRedirect keeps API keys (including nonstandard x-api-key headers) on the
// original scheme, host and port. net/http's default header filter does not
// recognize custom API-key headers, and allows some cross-origin redirects.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("重定向次数过多")
	}
	if len(via) == 0 {
		return nil
	}
	a, err := parseURL(via[0].URL.String(), false)
	if err != nil {
		return err
	}
	b, err := parseURL(req.URL.String(), false)
	if err != nil {
		return err
	}
	if a.Scheme != b.Scheme || a.Host != b.Host {
		return errors.New("拒绝向其他来源重定向携带凭据的请求")
	}
	return nil
}
