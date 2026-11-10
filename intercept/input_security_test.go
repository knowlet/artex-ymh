package intercept

import (
	"regexp"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func inputSecurityRule(id int64, target, kind, pattern, action string) compiledRule {
	r := compiledRule{InterceptRule: db.InterceptRule{
		ID: id, Name: "input-security", Enabled: true,
		MatchTarget: target, MatchType: kind, Pattern: pattern, Action: action,
	}}
	if kind == "regex" {
		r.re = regexp.MustCompile(pattern)
	}
	return r
}

func TestSecurityInterceptDecodedStrings(t *testing.T) {
	cases := []struct {
		name, kind, pattern, input string
		want                       bool
	}{
		{"plain", "string", "BLOCK_MARKER", "{\"command\":\"echo BLOCK_MARKER\"}", true},
		{"unicode", "string", "BLOCK_MARKER", "{\"command\":\"echo BLOCK_\\u004dARKER\"}", true},
		{"escaped slash", "string", "/admin/delete", "{\"url\":\"https:\\/\\/example.invalid\\/admin\\/delete\"}", true},
		{"tab", "regex", "BLOCK\\s+MARKER", "{\"command\":\"BLOCK\\tMARKER\"}", true},
		{"newline", "regex", "BLOCK\\s+MARKER", "{\"command\":\"BLOCK\\nMARKER\"}", true},
		{"nested array", "string", "BLOCK_MARKER", "{\"options\":[{\"values\":[\"BLOCK_\\u004dARKER\"]}]}", true},
		{"duplicate object members can merge", "string", "BLOCK_MARKER", "{\"options\":{\"value\":\"BLOCK_\\u004dARKER\"},\"options\":{\"other\":\"safe\"}}", true},
		{"escaped quote", "string", "\"BLOCK_MARKER\"", "{\"command\":\"echo \\\"BLOCK_MARKER\\\"\"}", true},
		{"unicode surrogate pair", "string", "🔒", "{\"value\":\"\\ud83d\\udd12\"}", true},
		{"legitimate", "string", "BLOCK_MARKER", "{\"command\":\"echo ordinary\"}", false},
		{"literal escape is not decoded twice", "string", "BLOCK_MARKER", "{\"command\":\"echo BLOCK_\\\\u004dARKER\"}", false},
		{"different fields are not concatenated", "string", "BLOCK_MARKER", "{\"first\":\"BLOCK_\",\"second\":\"MARKER\"}", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ic := &Interceptor{cached: []compiledRule{inputSecurityRule(1, "tool_input", tc.kind, tc.pattern, "deny")}}
			dec, matched := ic.Match("Bash", []byte(tc.input))
			if matched != tc.want || matched && (dec.Action != "deny" || dec.RuleID != 1) {
				t.Fatalf("match=%v decision=%+v, want match=%v", matched, dec, tc.want)
			}
		})
	}
}

func TestSecurityInterceptStructureAndPriority(t *testing.T) {
	structural := inputSecurityRule(1, "tool_input", "regex", "\"command\"\\s*:\\s*\"safe\"", "allow")
	deny := inputSecurityRule(2, "tool_input", "string", "safe", "deny")
	ic := &Interceptor{cached: []compiledRule{structural, deny}}
	if dec, matched := ic.Match("Bash", []byte(`{ "command" : "safe" }`)); !matched || dec.RuleID != 1 || dec.Action != "allow" {
		t.Fatalf("higher-priority structural rule changed: match=%v decision=%+v", matched, dec)
	}
	// Allow rules inspect raw JSON only; escaped spellings must not satisfy a raw regex via decoded subjects.
	if dec, matched := ic.Match("Bash", []byte(`{"\u0063ommand":"\u0073afe"}`)); !matched || dec.RuleID != 2 || dec.Action != "deny" {
		t.Fatalf("escaped spellings must not bypass raw allow rules: match=%v decision=%+v", matched, dec)
	}
	ask := inputSecurityRule(3, "tool_input", "string", "BLOCK_MARKER", "ask")
	allow := inputSecurityRule(4, "tool_name", "string", "Bash", "allow")
	ic = &Interceptor{cached: []compiledRule{ask, allow}}
	if dec, matched := ic.Match("Bash", []byte("{\"command\":\"BLOCK_\\u004dARKER\"}")); !matched || dec.RuleID != 3 || dec.Action != "ask" {
		t.Fatalf("decoded ask must retain priority over tool allow: %v %+v", matched, dec)
	}
	if dec, matched := ic.Match("Bash", nil); !matched || dec.RuleID != 4 || dec.Action != "allow" {
		t.Fatalf("empty no-argument input must preserve tool-name rules: %v %+v", matched, dec)
	}
	if _, matched := (&Interceptor{cached: []compiledRule{allow}}).Match("Read", []byte("{\"value\":\"Bash\"}")); matched {
		t.Fatal("tool-name rules started matching input values")
	}
}

func TestSecurityInterceptMalformedJSONFailsClosed(t *testing.T) {
	for _, rules := range [][]compiledRule{{}, {inputSecurityRule(1, "tool_name", "string", "Bash", "allow")}} {
		ic := &Interceptor{cached: rules}
		for _, input := range []string{"{", "{\"command\":\"safe\"} trailing", "{\"command\":\"safe\"}{}", "{\"command\":\"\\x41\"}", " "} {
			if dec, matched := ic.Match("Bash", []byte(input)); !matched || dec.Action != "deny" {
				t.Fatalf("malformed input was not rejected: %q match=%v decision=%+v", input, matched, dec)
			}
		}
	}
}
