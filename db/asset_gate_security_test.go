package db

import "testing"

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
	for _, host := range []string{"example.invalid", "123.example.invalid", "0x7f.example.invalid", "127.0.0.1.example.invalid", "192.0.2.1", "[2001:db8::1]"} {
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
		"0o177", "127_1", "08.0.0.1",
	} {
		if got := assetInterceptIP(host); got != nil {
			t.Errorf("invalid numeric host %q was reinterpreted as %s", host, got)
		}
	}
}
