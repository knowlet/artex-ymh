package db

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// 资产拦截规则的匹配/执行层。asset_intercept.go 只负责规则存储，这里负责把
// 「目标资产」的域名/IP/URL 与启用中的规则做匹配。供 agent 工具（add_intent、
// insert_assets）在下发意图 / 插入资产前调用，命中则拒绝。

// AssetInterceptKindLabel 返回 kind 的中文标签，用于给 agent 的说明消息。
func AssetInterceptKindLabel(kind string) string {
	switch kind {
	case "exact_domain":
		return "域名(全等)"
	case "exact_ip":
		return "IP(全等)"
	case "exact_url":
		return "URL(全等)"
	case "fuzzy_domain":
		return "域名(模糊)"
	case "fuzzy_ip":
		return "IP(模糊)"
	case "fuzzy_url":
		return "URL(模糊)"
	case "cidr":
		return "CIDR 网段"
	}
	return kind
}

// Reason 返回一条可读的命中原因，形如：命中资产拦截规则 [域名(模糊): .gov.cn]（备注）。
func (r AssetInterceptRule) Reason() string {
	s := fmt.Sprintf("命中资产拦截规则 [%s: %s]", AssetInterceptKindLabel(r.Kind), r.Pattern)
	if note := strings.TrimSpace(r.Note); note != "" {
		s += "（" + note + "）"
	}
	return s
}

// matchOne 判断单条启用规则是否命中给定的域名/IP/URL 候选串，返回命中的具体值。
func matchOne(r AssetInterceptRule, domains, ips, urls []string) (string, bool) {
	p := strings.TrimSpace(r.Pattern)
	if p == "" {
		return "", false
	}
	switch r.Kind {
	case "exact_domain":
		p = DomainKey(p)
		if p == "" {
			return "", false
		}
		for _, d := range domains {
			if strings.EqualFold(DomainKey(d), p) {
				return d, true
			}
		}
	case "exact_ip":
		want := net.ParseIP(p)
		if want == nil {
			return "", false
		}
		for _, ip := range ips {
			if got := net.ParseIP(strings.TrimSpace(ip)); got != nil && want.Equal(got) {
				return ip, true
			}
		}
	case "exact_url":
		for _, u := range urls {
			if strings.TrimSpace(u) == p {
				return u, true
			}
		}
	case "fuzzy_domain":
		lp := strings.ToLower(p)
		for _, d := range domains {
			if d != "" && strings.Contains(strings.ToLower(d), lp) {
				return d, true
			}
		}
	case "fuzzy_ip":
		for _, ip := range ips {
			if ip != "" && strings.Contains(ip, p) {
				return ip, true
			}
		}
	case "fuzzy_url":
		lp := strings.ToLower(p)
		for _, u := range urls {
			if u != "" && strings.Contains(strings.ToLower(u), lp) {
				return u, true
			}
		}
	case "cidr":
		_, ipnet, err := net.ParseCIDR(p)
		if err != nil {
			return "", false
		}
		for _, ip := range ips {
			if pip := net.ParseIP(strings.TrimSpace(ip)); pip != nil && ipnet.Contains(pip) {
				return ip, true
			}
		}
	}
	return "", false
}

// MatchAssetInterceptRules 返回第一条命中给定 域名/IP/URL 候选串的启用规则，及命中的具体值。
// 供 insert_assets 用原始输入（尚未落库的 assetInputItem）匹配。
func MatchAssetInterceptRules(rules []AssetInterceptRule, domains, ips, urls []string) (AssetInterceptRule, string, bool) {
	domains, ips = assetInterceptHosts(domains, ips, urls)
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if v, ok := matchOne(r, domains, ips, urls); ok {
			return r, v, true
		}
	}
	return AssetInterceptRule{}, "", false
}

// assetInterceptHosts is shared by insertion and stored-asset checks. Retain
// original candidates for existing domain/fuzzy rules, and add canonical IP
// candidates for numeric host spellings accepted by common URL clients. This
// is local parsing only; policy evaluation must never perform DNS lookups.
func assetInterceptHosts(domains, ips, urls []string) ([]string, []string) {
	domains = append([]string(nil), domains...)
	ips = append([]string(nil), ips...)
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		seen[ip] = true
	}
	addIP := func(host string) {
		if ip := assetInterceptIP(host); ip != nil {
			canonical := ip.String()
			if !seen[canonical] {
				ips = append(ips, canonical)
				seen[canonical] = true
			}
		}
	}
	for _, host := range domains {
		addIP(host)
	}
	for _, host := range ips {
		addIP(host)
	}
	for _, raw := range urls {
		if u, err := url.Parse(strings.TrimSpace(raw)); err == nil {
			if host := u.Hostname(); host != "" {
				if net.ParseIP(host) == nil {
					domains = append(domains, host)
				}
				addIP(host)
			}
		}
	}
	return domains, ips
}

// assetInterceptIP accepts canonical IP literals and the bounded inet_aton
// IPv4 forms: one to four decimal/octal/hex parts, with the final part filling
// the remaining bytes. It deliberately does not accept signs, underscores,
// overflow or arbitrary hostname resolution.
func assetInterceptIP(host string) net.IP {
	host = DomainKey(host)
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.IP(addr.WithZone("").AsSlice())
	}
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return nil
	}
	var value uint64
	for index, part := range parts {
		base, digits := 10, part
		if strings.HasPrefix(part, "0x") {
			base, digits = 16, part[2:]
		} else if len(part) > 1 && part[0] == '0' {
			base, digits = 8, part[1:]
		}
		if digits == "" {
			return nil
		}
		for _, ch := range digits {
			digit := -1
			if ch >= '0' && ch <= '9' {
				digit = int(ch - '0')
			} else if ch >= 'a' && ch <= 'f' {
				digit = int(ch-'a') + 10
			}
			if digit < 0 || digit >= base {
				return nil
			}
		}
		number, err := strconv.ParseUint(digits, base, 32)
		if err != nil {
			return nil
		}
		if index < len(parts)-1 {
			if number > 255 {
				return nil
			}
			value |= number << uint(8*(3-index))
		} else {
			if number >= uint64(1)<<uint(8*(5-len(parts))) {
				return nil
			}
			value |= number
		}
	}
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

// interceptCandidates 提取一个已落库资产用于拦截匹配的 域名/IP/URL 候选串。
// URL 的 host 会被拆出并归类，使「只带 URL」的服务类资产也能被 域名/IP 规则命中。
func (a *Asset) interceptCandidates() (domains, ips, urls []string) {
	add := func(dst *[]string, s string) {
		if s = strings.TrimSpace(s); s != "" {
			*dst = append(*dst, s)
		}
	}
	add(&domains, a.Domain)
	add(&domains, a.RootDomain)
	for _, d := range a.BoundDomains {
		add(&domains, d)
	}
	add(&ips, a.IP)
	add(&urls, a.URL)
	if a.URL != "" {
		if u, err := url.Parse(a.URL); err == nil {
			if h := u.Hostname(); h != "" {
				if net.ParseIP(h) != nil {
					add(&ips, h)
				} else {
					add(&domains, h)
				}
			}
		}
	}
	return domains, ips, urls
}

// InterceptLabel 返回资产的简短标识，用于给 agent 的说明消息。
func (a *Asset) InterceptLabel() string {
	var target string
	switch {
	case a.Domain != "":
		target = a.Domain
	case a.URL != "":
		target = a.URL
	case a.IP != "":
		target = a.IP
	default:
		target = fmt.Sprintf("#%d", a.ID)
	}
	return fmt.Sprintf("资产#%d[%s] %s", a.ID, a.Type, target)
}

// hasEnabledRule 判断规则集里是否存在任一启用规则。
func hasEnabledRule(rules []AssetInterceptRule) bool {
	for _, r := range rules {
		if r.Enabled {
			return true
		}
	}
	return false
}

// AssetGateDecision 是「先拦截后允许」闸门对一组候选串的判定结果。
type AssetGateDecision struct {
	Allowed bool
	Reason  string // 被拒原因（不含资产标识）；Allowed=true 时为空
}

// EvaluateAssetGate 执行任务级闸门判定：
//  1. 命中任一启用的 blockRules → 拒绝（拦截原因）。
//  2. 否则若 allowRules 存在启用项且都不命中 → 拒绝（不在允许范围）。
//  3. 否则放行。
//
// allowRules 为空/无启用项时，允许闸门不生效（即不启用白名单，全部放行），
// 避免「未配置允许规则」把所有资产挡掉。
func EvaluateAssetGate(blockRules, allowRules []AssetInterceptRule, domains, ips, urls []string) AssetGateDecision {
	if rule, _, ok := MatchAssetInterceptRules(blockRules, domains, ips, urls); ok {
		return AssetGateDecision{Allowed: false, Reason: rule.Reason()}
	}
	if hasEnabledRule(allowRules) {
		if _, _, ok := MatchAssetInterceptRules(allowRules, domains, ips, urls); !ok {
			return AssetGateDecision{Allowed: false, Reason: "不在任务允许(白名单)范围内，不允许测试"}
		}
	}
	return AssetGateDecision{Allowed: true}
}

// AssetInterceptHit 描述一个被闸门拒绝的资产（拦截命中 或 不在允许范围）。
type AssetInterceptHit struct {
	Asset  *Asset
	Reason string // 可读原因
}

// Describe 返回一条可读的说明：资产信息 + 原因。
func (h AssetInterceptHit) Describe() string {
	return fmt.Sprintf("%s → %s", h.Asset.InterceptLabel(), h.Reason)
}

// ListAssetInterceptRules 是 *DB 同名方法的透传，让只持有 AssetStore 的调用方
// （如 agent 工具）也能读取规则。
func (s *AssetStore) ListAssetInterceptRules() ([]AssetInterceptRule, error) {
	return s.db.ListAssetInterceptRules()
}

// CheckAssetsIntercept 按 id 载入资产，逐个执行「先拦截后允许」闸门判定，返回所有
// 被拒的资产。拦截规则 = 全局 ∪ 任务级 block；允许规则 = 任务级 allow（仅本任务）。
// 无 id 时快速返回。用全局 GetByIDs（不受任务范围过滤）以保证拦截不被 scope 削弱。
func (s *AssetStore) CheckAssetsIntercept(taskID int64, ids []int64) ([]AssetInterceptHit, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	blockRules, err := s.db.ListAssetInterceptRules()
	if err != nil {
		return nil, err
	}
	var allowRules []AssetInterceptRule
	if taskID > 0 {
		tb, ta, err := s.TaskInterceptRulesSplit(taskID)
		if err != nil {
			return nil, err
		}
		blockRules = append(blockRules, tb...)
		allowRules = ta
	}
	// 既无拦截规则、也无启用的允许规则 → 无需判定，全部放行。
	if len(blockRules) == 0 && !hasEnabledRule(allowRules) {
		return nil, nil
	}
	assets, err := s.GetByIDs(ids)
	if err != nil {
		return nil, err
	}
	var hits []AssetInterceptHit
	for _, a := range assets {
		domains, ips, urls := a.interceptCandidates()
		if d := EvaluateAssetGate(blockRules, allowRules, domains, ips, urls); !d.Allowed {
			hits = append(hits, AssetInterceptHit{Asset: a, Reason: d.Reason})
		}
	}
	return hits, nil
}
