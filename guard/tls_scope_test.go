package guard

import (
	"context"
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
