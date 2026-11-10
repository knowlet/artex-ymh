package agent

import (
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
		{Type: "subdomain", Domain: "ordinary.example", BoundDomains: []string{"internal.example."}},
	} {
		domains, ips, urls := assetInterceptCandidates(item)
		if d := db.EvaluateAssetGate(block, nil, domains, ips, urls); d.Allowed {
			t.Errorf("insertion adapter bypassed canonical rules: %+v", item)
		}
	}
	for _, item := range []assetInputItem{
		{Type: "subdomain", Domain: "ordinary.example"},
		{Type: "subdomain", Domain: "child.internal.example"},
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
