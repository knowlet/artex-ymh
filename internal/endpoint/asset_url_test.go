package endpoint

import "testing"

func TestValidateAssetURL(t *testing.T) {
	for _, raw := range []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"ftp://example.com/",
		"relative/path",
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
	} {
		if err := ValidateAssetURL(raw); err != nil {
			t.Fatalf("ValidateAssetURL(%q) should succeed: %v", raw, err)
		}
	}
}
