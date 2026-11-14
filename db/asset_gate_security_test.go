package db

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"golang.org/x/net/idna"
)

func TestSecurityAssetExactDomainCanonicalization(t *testing.T) {
	for _, pattern := range []string{"internal.example", "INTERNAL.EXAMPLE.", " internal.example. "} {
		block := []AssetInterceptRule{rule("exact_domain", pattern, true)}
		for _, domain := range []string{"internal.example", "INTERNAL.EXAMPLE.", " internal.example. "} {
			if d := EvaluateAssetGate(block, nil, []string{domain}, nil, nil); d.Allowed {
				t.Errorf("equivalent exact domain allowed: rule=%q candidate=%q", pattern, domain)
			}
		}
		for _, domain := range []string{"other.example", "child.internal.example", "notinternal.example"} {
			if d := EvaluateAssetGate(block, nil, []string{domain}, nil, nil); !d.Allowed {
				t.Errorf("distinct domain incorrectly blocked: rule=%q candidate=%q", pattern, domain)
			}
		}
		if d := EvaluateAssetGate(block, block, []string{"internal.example."}, nil, nil); d.Allowed {
			t.Fatal("canonical allow rule overrode a matching block rule")
		}
		if d := EvaluateAssetGate(nil, block, []string{"INTERNAL.EXAMPLE."}, nil, nil); !d.Allowed {
			t.Fatal("canonical exact-domain allow rule stopped matching")
		}
	}
}

func TestSecurityAssetNumericURLHosts(t *testing.T) {
	hosts := []string{
		"127.0.0.1", "2130706433", "127.1", "127.0.1", "0177.0.0.1",
		"0x7f000001", "0X7F.1", "017700000001", "127.0.0.1.",
		"127。0。0。1", "127．0．0．1", "127｡0｡0｡1", "１２７.０.０.１",
		"１２７。０。０。１。", "2130706433。",
		"[::ffff:127.0.0.1]",
	}
	for _, kind := range []string{"exact_ip", "cidr", "fuzzy_ip"} {
		pattern := map[string]string{"exact_ip": "127.0.0.1", "cidr": "127.0.0.0/8", "fuzzy_ip": "127."}[kind]
		block := []AssetInterceptRule{rule(kind, pattern, true)}
		for _, host := range hosts {
			t.Run(kind+"/"+host, func(t *testing.T) {
				// Exercise the stored-asset adapter as well as the shared gate.
				a := &Asset{Type: "service", URL: "http://" + host + ":8080/path"}
				domains, ips, urls := a.interceptCandidates()
				if d := EvaluateAssetGate(block, nil, domains, ips, urls); d.Allowed {
					t.Fatalf("numeric host missed canonical %s policy: %q", kind, host)
				}
				if d := EvaluateAssetGate(block, nil, nil, nil, []string{a.URL}); d.Allowed {
					t.Fatal("URL-only candidates bypassed the shared matcher")
				}
			})
		}
	}
}

func TestSecurityAssetHostNormalizationControls(t *testing.T) {
	block := []AssetInterceptRule{rule("cidr", "127.0.0.0/8", true)}
	for _, host := range []string{"example.invalid", "123.example.invalid", "0x7f.example.invalid", "127.0.0.1.example.invalid", "１２７.０.０.１.example.invalid", "bücher.example", "192.0.2.1", "[2001:db8::1]"} {
		if d := EvaluateAssetGate(block, nil, nil, nil, []string{"https://" + host + "/"}); !d.Allowed {
			t.Errorf("ordinary host incorrectly blocked: %q", host)
		}
	}
	for _, host := range []string{"2130706433", "127.1", "0177.0.0.1", "0x7f000001"} {
		// Keep original domain/URL representations available to configured rules.
		domainBlock := []AssetInterceptRule{rule("exact_domain", host, true)}
		if d := EvaluateAssetGate(domainBlock, nil, []string{host}, nil, nil); d.Allowed {
			t.Errorf("original exact-domain policy stopped matching: %q", host)
		}
		if d := EvaluateAssetGate(block, nil, []string{host}, nil, nil); d.Allowed {
			t.Errorf("numeric domain candidate missed IP policy: %q", host)
		}
	}
	for _, input := range []struct{ pattern, candidate string }{
		{"2001:db8::1", "2001:0db8:0:0:0:0:0:1"},
		{"127.0.0.1", "::ffff:127.0.0.1"},
	} {
		if d := EvaluateAssetGate([]AssetInterceptRule{rule("exact_ip", input.pattern, true)}, nil, nil, []string{input.candidate}, nil); d.Allowed {
			t.Errorf("equivalent canonical IP spelling missed: %+v", input)
		}
	}
}

func TestSecurityAssetLegacyIPParseBounds(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"0", "0.0.0.0"},
		{"4294967295", "255.255.255.255"},
		{"0xffffffff", "255.255.255.255"},
		{"0377.0377.0377.0377", "255.255.255.255"},
		{"1.16777215", "1.255.255.255"},
		{"1.2.65535", "1.2.255.255"},
		{"0300.0000.0002.0001", "192.0.2.1"},
		{"2001:0db8:0:0:0:0:0:1", "2001:db8::1"},
		{"fe80::1%eth0", "fe80::1"},
	} {
		if got := assetInterceptIP(tc.host); got == nil || got.String() != tc.want {
			t.Errorf("numeric parse %q = %v, want %q", tc.host, got, tc.want)
		}
	}
	for _, host := range []string{
		"", "example.invalid", "123.example.invalid", "1.2.3.4.5",
		"4294967296", "0x100000000", "040000000000", "256.1", "1.16777216",
		"1.2.65536", "1.2.3.256", "1..2", "+127.1", "-1", "0x", "0b1111111",
		"0o177", "127_1", "08.0.0.1", "127.0.0.1..", "１２７.０.０.１..", "127\u200d.0.0.1",
	} {
		if got := assetInterceptIP(host); got != nil {
			t.Errorf("invalid numeric host %q was reinterpreted as %s", host, got)
		}
	}
}

func TestSecurityAssetIDNAExactDomains(t *testing.T) {
	for _, pair := range [][2]string{
		{"internal.example", "internal.example。"},
		{"internal.example", "INTERNAL。EXAMPLE"},
		{"internal.example", "internal．example．"},
		{"internal.example", "internal｡example｡"},
		{"internal.example", "ｉｎｔｅｒｎａｌ.example"},
		{"xn--bcher-kva.example", "bücher.example"},
		{"xn--bcher-kva.example", "BÜCHER。EXAMPLE．"},
	} {
		// Both rule-side and candidate-side spellings describe the same host.
		for _, reverse := range []bool{false, true} {
			pattern, candidate := pair[0], pair[1]
			if reverse {
				pattern, candidate = candidate, pattern
			}
			rules := []AssetInterceptRule{rule("exact_domain", pattern, true)}
			for _, asset := range []*Asset{
				{Type: "subdomain", Domain: candidate},
				{Type: "service", URL: "https://" + candidate + "/path"},
			} {
				domains, ips, urls := asset.interceptCandidates()
				if d := EvaluateAssetGate(rules, nil, domains, ips, urls); d.Allowed {
					t.Errorf("equivalent host escaped block: pattern=%q candidate=%q", pattern, candidate)
				}
				if d := EvaluateAssetGate(nil, rules, domains, ips, urls); !d.Allowed {
					t.Errorf("equivalent host missed allow: pattern=%q candidate=%q", pattern, candidate)
				}
			}
		}
	}
	for _, pair := range [][2]string{
		{"internal.example", "child.internal。example"},
		{"internal.example", "notinternal.example"},
		{"internal.example", "internal.example.."},
		{"internal.example", "internal.example。。"},
		{"fass.example", "faß.example"}, // Lookup uses non-transitional IDNA.
	} {
		if d := EvaluateAssetGate([]AssetInterceptRule{rule("exact_domain", pair[0], true)}, nil, []string{pair[1]}, nil, nil); !d.Allowed {
			t.Errorf("distinct host matched exact-domain policy: %q / %q", pair[0], pair[1])
		}
	}
}

func TestSecurityAssetIDNAStoredCaseNormalization(t *testing.T) {
	// Go's existing storage case mapping turns U+0130 into ASCII i. IDNA run
	// first would instead produce a different host and change the gate at save.
	rawHost := "İnternal.example"
	storedHost := DomainKey(rawHost)
	rawURL := "http://" + rawHost + "/path"
	storedURL := normalizeURL(rawURL)
	urlHost, _, _ := parseURL(storedURL)
	if storedHost != "internal.example" || urlHost != storedHost {
		t.Fatal("fixture must exercise the actual storage case normalization")
	}
	for _, pattern := range []string{rawHost, storedHost} {
		rules := []AssetInterceptRule{rule("exact_domain", pattern, true)}
		for _, pair := range [][2]*Asset{
			{{Type: "subdomain", Domain: rawHost}, {Type: "subdomain", Domain: storedHost}},
			{{Type: "service", URL: rawURL}, {Type: "service", URL: storedURL}},
		} {
			for stage, asset := range pair {
				domains, ips, urls := asset.interceptCandidates()
				if d := EvaluateAssetGate(rules, nil, domains, ips, urls); d.Allowed {
					t.Errorf("block differs from stored host: pattern=%q stage=%d domain=%q URL=%q", pattern, stage, asset.Domain, asset.URL)
				}
				if d := EvaluateAssetGate(nil, rules, domains, ips, urls); !d.Allowed {
					t.Errorf("allow differs from stored host: pattern=%q stage=%d domain=%q URL=%q", pattern, stage, asset.Domain, asset.URL)
				}
			}
		}
	}
}

func TestSecurityAssetIDNAUsesActualHTTPDestination(t *testing.T) {
	for _, tc := range []struct{ host, kind, pattern, address string }{
		{"127。0。0。1", "cidr", "127.0.0.0/8", "127.0.0.1:80"},
		{"127．0．0．1", "cidr", "127.0.0.0/8", "127.0.0.1:80"},
		{"127｡0｡0｡1", "cidr", "127.0.0.0/8", "127.0.0.1:80"},
		{"１２７.０.０.１", "exact_ip", "127.0.0.1", "127.0.0.1:80"},
		{"internal.example。", "exact_domain", "internal.example", "internal.example.:80"},
		{"bücher.example", "exact_domain", "xn--bcher-kva.example", "xn--bcher-kva.example:80"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			// Record Transport's real IDNA conversion but never resolve or dial.
			addresses := make(chan string, 1)
			transport := &http.Transport{DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
				addresses <- address
				return nil, errors.New("synthetic dial stopped before network access")
			}}
			defer transport.CloseIdleConnections()
			raw := "http://" + tc.host + "/"
			req, err := http.NewRequest(http.MethodGet, raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp, err := (&http.Client{Transport: transport}).Do(req); err == nil || resp != nil {
				t.Fatal("synthetic dial unexpectedly completed")
			}
			select {
			case address := <-addresses:
				if address != tc.address {
					t.Fatalf("HTTP destination=%q, want %q", address, tc.address)
				}
			default:
				t.Fatal("HTTP transport did not reach the no-network dial stub")
			}
			if d := EvaluateAssetGate([]AssetInterceptRule{rule(tc.kind, tc.pattern, true)}, nil, nil, nil, []string{raw}); d.Allowed {
				t.Fatalf("asset policy missed HTTP destination %s", tc.address)
			}
		})
	}
}

func TestSecurityAssetIDNAKeepsOriginalAndInvalidCandidates(t *testing.T) {
	for _, tc := range []struct{ kind, pattern string }{
		{"fuzzy_domain", "bücher"},
		{"fuzzy_url", "bücher"},
		{"exact_url", "https://bücher.example/"},
	} {
		if d := EvaluateAssetGate([]AssetInterceptRule{rule(tc.kind, tc.pattern, true)}, nil, nil, nil, []string{"https://bücher.example/"}); d.Allowed {
			t.Errorf("original %s candidate was discarded", tc.kind)
		}
	}
	if d := EvaluateAssetGate([]AssetInterceptRule{rule("fuzzy_ip", "１２７", true)}, nil, nil, []string{"１２７.０.０.１"}, nil); d.Allowed {
		t.Fatal("original fuzzy-IP candidate was discarded")
	}
	// IDNA can return a partially converted name together with an error. That
	// result is not an equivalence proof and must not grant a hostname allow.
	invalid := "bad\u200d.example"
	partial, err := idna.Lookup.ToASCII(invalid)
	if err == nil || partial == invalid {
		t.Fatal("fixture must produce a partial IDNA result with an error")
	}
	if d := EvaluateAssetGate(nil, []AssetInterceptRule{rule("exact_domain", partial, true)}, []string{invalid}, nil, nil); d.Allowed {
		t.Fatal("invalid Unicode host inherited a partial-IDNA hostname allow")
	}
	for _, host := range []string{"service_name.internal", "bad_label.example", invalid} {
		if d := EvaluateAssetGate([]AssetInterceptRule{rule("exact_domain", host, true)}, nil, []string{host}, nil, nil); d.Allowed {
			t.Errorf("explicit literal policy for non-IDNA name changed: %q", host)
		}
	}
}
