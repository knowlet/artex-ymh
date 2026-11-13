package endpoint

import (
	"fmt"
	"testing"
)

func TestValidateAssetURL(t *testing.T) {
	for _, raw := range []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"ftp://example.com/",
		"relative/path",
		"https://",
		"https:///path",
		"https://:443/path",
		"https:example.com/path",
		"",
		"   ",
	} {
		if err := ValidateAssetURL(raw); err == nil {
			t.Fatalf("ValidateAssetURL(%q) should fail", raw)
		}
	}
	for _, raw := range []string{
		"https://example.com/",
		"http://Example.COM/path",
		"https://example.com/#/dashboard",
		"https://example.com/path?q=1#frag",
		"https://user:pass@example.com/", // scheme gate only; userinfo preserved for legacy rows
		"http://localhost:8080/path",
		"https://[::1]:8443/path#fragment",
		"https://example.com/a%20b?q=two%20words#frag",
		"https://example.com/中文?q=繁體#片段",
	} {
		if err := ValidateAssetURL(raw); err != nil {
			t.Fatalf("ValidateAssetURL(%q) should succeed: %v", raw, err)
		}
	}
}

func TestValidateAssetURLRejectsWhitespaceAndControl(t *testing.T) {
	// Validation must inspect the bytes the caller will persist. Sanitizing only
	// a temporary copy lets url.Parse fail later and lose the asset's host/port.
	for _, raw := range []string{
		" https://example.com/",
		"https://example.com/ ",
		"ht tps://example.com/",
		"https://exa mple.com/",
		"https://example.com/a b",
		"https://example.com/?q=two words",
		"https://example.com/#two words",
		"https://exam\u00a0ple.com/",
		"https://example.com/\u0085path",
		"https://example.com/\u2028path",
	} {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			if err := ValidateAssetURL(raw); err == nil {
				t.Errorf("ValidateAssetURL(%q) accepted whitespace", raw)
			}
		})
	}
	for _, r := range append([]rune{0x7f, 0x85}, []rune("\x00\x01\t\n\r\x1f")...) {
		raw := "https://example.com/" + string(r) + "path"
		t.Run(fmt.Sprintf("control_U+%04X", r), func(t *testing.T) {
			if err := ValidateAssetURL(raw); err == nil {
				t.Errorf("ValidateAssetURL(%q) accepted a control character", raw)
			}
		})
	}
}
