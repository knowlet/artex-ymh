package guard

import (
	"context"
	"net"
	"testing"
)

func TestInsecureTLSRequiresExplicitTaskScope(t *testing.T) {
	for _, mode := range []string{"strict", "warn", "off"} {
		t.Run(mode, func(t *testing.T) {
			for _, test := range []struct {
				name    string
				host    string
				rules   []ScopeRule
				allowed bool
			}{
				{"matching IP", "192.0.2.9", []ScopeRule{{Kind: "ip", Value: "192.0.2.9"}}, true},
				{"matching CIDR", "192.0.2.9", []ScopeRule{{Kind: "cidr", Value: "192.0.2.0/24"}}, true},
				{"matching domain", "api.target.example", []ScopeRule{{Kind: "domain", Value: "target.example"}}, true},
				{"matching IPv6", "2001:db8::2", []ScopeRule{{Kind: "cidr", Value: "2001:db8::/32"}}, true},
				{"explicit localhost", "localhost", []ScopeRule{{Kind: "domain", Value: "localhost"}}, true},
				{"outside", "outside.example", []ScopeRule{{Kind: "domain", Value: "target.example"}}, false},
				{"no rules", "192.0.2.9", nil, false},
				{"invalid rules", "192.0.2.9", []ScopeRule{{Kind: "cidr", Value: "invalid"}}, false},
				{"keyword only", "target.example", []ScopeRule{{Kind: "keyword", Value: "target"}}, false},
				{"loopback exemption disallowed", "127.0.0.1", []ScopeRule{{Kind: "domain", Value: "target.example"}}, false},
				{"linklocal exemption disallowed", "169.254.169.254", []ScopeRule{{Kind: "domain", Value: "target.example"}}, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					g := roeGuard(mode, test.rules)
					err := g.AuthorizeInsecureTLS(t.Context(), test.host)
					if (err == nil) != test.allowed {
						t.Fatalf("authorized=%v, want %v; error=%v", err == nil, test.allowed, err)
					}
				})
			}
		})
	}
	for _, g := range []*Guard{nil, New(), func() *Guard {
		g := New()
		g.SetRoE(RoEConfig{Scope: func(int64) []ScopeRule { return []ScopeRule{{Kind: "ip", Value: "127.0.0.1"}} }, TaskIDOf: func(context.Context) int64 { return 0 }})
		return g
	}()} {
		if err := g.AuthorizeInsecureTLS(t.Context(), "127.0.0.1"); err == nil {
			t.Fatal("missing task/scope guard authorized a TLS exception")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := roeGuard("strict", []ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}).AuthorizeInsecureTLS(ctx, "127.0.0.1"); err != context.Canceled {
		t.Fatalf("canceled TLS exception error=%v", err)
	}
}

func TestInsecureTLSResolvedAddressScope(t *testing.T) {
	for _, test := range []struct {
		name    string
		host    string
		ip      string
		extra   []ScopeRule
		allowed bool
	}{
		{"domain public IPv4", "target.example", "203.0.113.9", nil, true},
		{"domain private IPv4", "target.example", "192.168.50.10", nil, true},
		{"domain public IPv6", "target.example", "2001:db8::9", nil, true},
		{"domain private IPv6", "target.example", "fd00::9", nil, true},
		{"loopback requires IP", "target.example", "127.0.0.1", nil, false},
		{"linklocal requires IP", "target.example", "169.254.169.254", nil, false},
		{"IPv6 loopback", "target.example", "::1", nil, false},
		{"IPv6 linklocal", "target.example", "fe80::1", nil, false},
		{"IPv4 mapped loopback", "target.example", "::ffff:127.0.0.1", nil, false},
		{"IPv4 mapped linklocal", "target.example", "::ffff:169.254.169.254", nil, false},
		{"IPv4 unspecified", "target.example", "0.0.0.0", nil, false},
		{"IPv6 unspecified", "target.example", "::", nil, false},
		{"IPv4 multicast", "target.example", "224.0.0.1", nil, false},
		{"IPv6 multicast", "target.example", "ff02::1", nil, false},
		{"IPv4 broadcast", "target.example", "255.255.255.255", nil, false},
		{"explicit loopback IP", "target.example", "127.0.0.1", []ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}, true},
		{"explicit linklocal CIDR", "target.example", "169.254.169.254", []ScopeRule{{Kind: "cidr", Value: "169.254.0.0/16"}}, true},
		{"explicit IPv6 local CIDR", "target.example", "fe80::1", []ScopeRule{{Kind: "cidr", Value: "fe80::/10"}}, true},
		{"IP literal still scoped", "127.0.0.1", "127.0.0.1", []ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}, true},
		{"hostname remains required", "outside.example", "203.0.113.9", nil, false},
		{"nil IP", "target.example", "not-an-ip", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			rules := append([]ScopeRule{{Kind: "domain", Value: "target.example"}}, test.extra...)
			err := roeGuard("off", rules).AuthorizeInsecureTLSAddress(t.Context(), test.host, net.ParseIP(test.ip))
			if (err == nil) != test.allowed {
				t.Fatalf("authorized=%v, want %v: %v", err == nil, test.allowed, err)
			}
		})
	}
}
