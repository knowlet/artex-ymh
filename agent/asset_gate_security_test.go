package agent

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSecurityInsertAssetCandidatesHonorCanonicalRules(t *testing.T) {
	block := []db.AssetInterceptRule{
		{Kind: "exact_domain", Pattern: "internal.example", Enabled: true},
		{Kind: "cidr", Pattern: "127.0.0.0/8", Enabled: true},
	}
	for _, item := range []assetInputItem{
		{Type: "subdomain", Domain: "internal.example."},
		{Type: "service", URL: "http://internal.example.:8080/"},
		{Type: "service", URL: "http://2130706433/"},
		{Type: "endpoint", URL: "http://127.1/path"},
		{Type: "service", URL: "http://0177.0.0.1/"},
		{Type: "service", URL: "http://0x7f000001/"},
		{Type: "service", URL: "http://127。0。0。1/"},
		{Type: "endpoint", URL: "http://１２７.０.０.１/path"},
		{Type: "service", URL: "http://internal.example。/"},
		{Type: "subdomain", Domain: "ｉｎｔｅｒｎａｌ.example"},
		{Type: "subdomain", Domain: "ordinary.example", BoundDomains: []string{"internal.example."}},
		{Type: "subdomain", Domain: "ordinary.example", BoundDomains: []string{"internal｡example"}},
	} {
		domains, ips, urls := assetInterceptCandidates(item)
		if d := db.EvaluateAssetGate(block, nil, domains, ips, urls); d.Allowed {
			t.Errorf("insertion adapter bypassed canonical rules: %+v", item)
		}
	}
	for _, item := range []assetInputItem{
		{Type: "subdomain", Domain: "ordinary.example"},
		{Type: "subdomain", Domain: "child.internal.example"},
		{Type: "subdomain", Domain: "child.internal。example"},
		{Type: "service", URL: "http://１２７.０.０.１.example.invalid/"},
		{Type: "service", URL: "https://123.example.invalid/path"},
		{Type: "service", URL: "http://192.0.2.1/"},
		{Type: "service", URL: "http://[2001:db8::1]/"},
	} {
		domains, ips, urls := assetInterceptCandidates(item)
		if d := db.EvaluateAssetGate(block, nil, domains, ips, urls); !d.Allowed {
			t.Errorf("legitimate insertion candidate rejected: %+v", item)
		}
	}
}

func TestSecurityInsertAssetStoredCaseNormalization(t *testing.T) {
	rawHost := "İnternal.example"
	storedHost := db.DomainKey(rawHost)
	if storedHost != "internal.example" {
		t.Fatal("fixture must exercise storage's Unicode case normalization")
	}
	for _, pattern := range []string{rawHost, storedHost} {
		rules := []db.AssetInterceptRule{{Kind: "exact_domain", Pattern: pattern, Enabled: true}}
		for _, item := range []assetInputItem{
			{Type: "subdomain", Domain: rawHost},
			{Type: "subdomain", Domain: storedHost},
			{Type: "service", URL: "http://" + rawHost + "/"},
			{Type: "endpoint", URL: "http://" + rawHost + "/path"},
			{Type: "subdomain", Domain: "ordinary.example", BoundDomains: []string{rawHost}},
		} {
			domains, ips, urls := assetInterceptCandidates(item)
			if d := db.EvaluateAssetGate(rules, nil, domains, ips, urls); d.Allowed {
				t.Errorf("insertion missed stored-host block: pattern=%q item=%+v", pattern, item)
			}
			if d := db.EvaluateAssetGate(nil, rules, domains, ips, urls); !d.Allowed {
				t.Errorf("insertion missed stored-host allow: pattern=%q item=%+v", pattern, item)
			}
		}
	}
}

func TestSecurityInsertAssetRejectsStoredRootSeparatorMismatch(t *testing.T) {
	block := []db.AssetInterceptRule{{Kind: "exact_domain", Pattern: "internal.example", Enabled: true}}
	// Preserve the shared matcher's literal semantics: malformed double roots
	// are not aliases for a valid host, even though storage removes one dot.
	for _, raw := range []string{"internal.example..", "internal.example.\u200b.", "internal.example.\u00ad."} {
		stored := db.DomainKey(raw)
		if stored != strings.TrimSuffix(raw, ".") || !db.EvaluateAssetGate(block, nil, []string{raw}, nil, nil).Allowed ||
			db.EvaluateAssetGate(block, nil, []string{stored}, nil, nil).Allowed {
			t.Fatalf("fixture must reproduce the raw-to-stored policy mismatch: %q", raw)
		}
		for _, typ := range []string{"root_domain", "subdomain"} {
			if d := evaluateAssetInputGate(block, nil, assetInputItem{Type: typ, Domain: raw}); d.Allowed || d.Reason == "" {
				t.Errorf("%s %q with repeated root separators reached the insertion boundary: %+v", typ, raw, d)
			}
		}
	}
}

func TestSecurityInsertAssetRejectsRepeatedRootSeparators(t *testing.T) {
	for _, suffix := range []string{"..", "...", "。。", "．．", "｡｡", ".。", "。.", "．｡", ".\u200b.", ".\u00ad."} {
		host := "ordinary.example" + suffix
		for _, withAllow := range []bool{false, true} {
			var allow []db.AssetInterceptRule
			if withAllow {
				allow = []db.AssetInterceptRule{{Kind: "exact_domain", Pattern: host, Enabled: true}}
				if !db.EvaluateAssetGate(nil, allow, []string{host}, nil, nil).Allowed {
					t.Fatal("fixture must show a literal malformed allow rule cannot override input validation")
				}
			}
			for _, item := range []assetInputItem{
				{Type: "root_domain", Domain: " \t" + host + "\n"},
				{Type: "subdomain", Domain: host},
				{Type: "service", Domain: host, ServiceName: "ssh", Port: 22},
				{Type: "service", URL: " \thttp://" + host + ":8080/path \n"},
				{Type: "endpoint", URL: "https://" + host + "/path"},
				{Type: "ip", IP: "192.0.2.1", BoundDomains: []string{"valid.example", " " + host + " "}},
			} {
				if d := evaluateAssetInputGate(nil, allow, item); d.Allowed || d.Reason == "" {
					t.Errorf("malformed root suffix reached insertion: allow=%t item=%+v decision=%+v", withAllow, item, d)
				}
			}
		}
	}
}

func TestSecurityInsertAssetGateKeepsValidCandidates(t *testing.T) {
	block := []db.AssetInterceptRule{{Kind: "exact_domain", Pattern: "internal.example", Enabled: true}}
	for _, host := range []string{
		"ordinary.example", "ordinary.example.", "ordinary.example。", "ordinary.example．", "ordinary.example｡",
		"ordinary.example.\u200b", "ordinary.example\u00ad.",
		"bücher.example", "service_name.internal", "child.internal.example", "ｏｒｄｉｎａｒｙ.example",
	} {
		allow := []db.AssetInterceptRule{{Kind: "exact_domain", Pattern: host, Enabled: true}}
		for _, item := range []assetInputItem{
			{Type: "subdomain", Domain: host},
			{Type: "service", URL: "https://" + host + "/path..?suffix=。｡"},
		} {
			if d := evaluateAssetInputGate(nil, nil, item); !d.Allowed {
				t.Errorf("valid input rejected without rules: %+v: %s", item, d.Reason)
			}
			if d := evaluateAssetInputGate(block, allow, item); !d.Allowed {
				t.Errorf("valid input rejected by configured policy: %+v: %s", item, d.Reason)
			}
		}
	}
	for _, host := range []string{"internal.example.", "İnternal.example", "internal。example"} {
		item := assetInputItem{Type: "service", URL: "http://" + host + "/"}
		if d := evaluateAssetInputGate(block, nil, item); d.Allowed || !strings.Contains(d.Reason, "internal.example") {
			t.Errorf("insertion stopped applying the existing block: %q: %+v", host, d)
		}
		if d := evaluateAssetInputGate(nil, block, item); !d.Allowed {
			t.Errorf("insertion stopped applying the existing allow: %q: %+v", host, d)
		}
	}
	if d := evaluateAssetInputGate(nil, nil, assetInputItem{Type: "service", URL: "http://[2001:db8::1]/"}); !d.Allowed {
		t.Fatal("valid IPv6 URL rejected")
	}
}

func TestSecurityInsertAssetScopedIPv6KeepsIPRules(t *testing.T) {
	item := assetInputItem{Type: "service", URL: "http://[fe80::1%25test..]/"}
	u, err := url.Parse(item.URL)
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddr(u.Hostname())
	if err != nil || address.Zone() != "test.." {
		t.Fatalf("fixture must be a valid scoped IPv6 address: %v", err)
	}
	if d := evaluateAssetInputGate(nil, nil, item); !d.Allowed {
		t.Errorf("valid IPv6 zone dots were treated as DNS separators: %s", d.Reason)
	}
	for _, rule := range []db.AssetInterceptRule{
		{Kind: "exact_ip", Pattern: "fe80::1", Enabled: true},
		{Kind: "cidr", Pattern: "fe80::/10", Enabled: true},
	} {
		rules := []db.AssetInterceptRule{rule}
		if d := evaluateAssetInputGate(rules, nil, item); d.Allowed || !strings.Contains(d.Reason, rule.Pattern) {
			t.Errorf("valid scoped IPv6 address bypassed %s policy: %+v", rule.Kind, d)
		}
		if d := evaluateAssetInputGate(nil, rules, item); !d.Allowed {
			t.Errorf("valid scoped IPv6 address missed %s allow: %s", rule.Kind, d.Reason)
		}
	}
}
