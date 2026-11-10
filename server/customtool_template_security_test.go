package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestSecurityTemplateSubstitutionsAreLiteral(t *testing.T) {
	// Either map iteration order used to rescan one of these inserted values.
	params := map[string]any{"a": "{b}", "b": "{a}"}
	if got := renderTemplate("{a}|{b}|{a}", params, shellQuote); got != "'{b}'|'{a}'|'{b}'" {
		t.Fatalf("parameter text was expanded as another placeholder: %q", got)
	}
	for range 64 {
		got := renderTemplate("printf %s {args}", map[string]any{
			"args": "{extra}", "extra": ";printf UNEXPECTED_COMMAND;",
		}, shellQuote)
		if got != "printf %s '{extra}'" {
			t.Fatalf("an unused parameter changed inserted argument text: %q", got)
		}
	}
}

func TestSecurityTemplateCommandKeepsExtraParamsAsData(t *testing.T) {
	// The default args schema tolerates additional properties. Exercise that
	// actual tool adapter and the local shell with printf only, without writes.
	spec, err := json.Marshal(commandExec{Command: "printf '<%s>' {args}"})
	if err != nil {
		t.Fatal(err)
	}
	tool := (&Server{}).buildCustomTool(&db.Tool{Key: "template_fixture", Kind: "command", Exec: spec})
	input, _ := json.Marshal(map[string]any{"args": "{extra}", "extra": ";printf UNEXPECTED_COMMAND;"})
	if err := actool.ValidateInput(tool.InputSchema(), input); err != nil {
		t.Fatal(err)
	}
	for range 16 {
		result, err := tool.Call(context.Background(), input, &actool.ToolContext{WorkingDir: t.TempDir()})
		if err != nil || result.IsError || strings.TrimSpace(result.Flatten()) != "<{extra}>" {
			t.Fatalf("extra parameter escaped its argument: err=%v output=%q", err, result.Flatten())
		}
	}
}

func TestSecurityTemplatePreservesOrdinaryValues(t *testing.T) {
	cases := []struct {
		name, template, want string
		params               map[string]any
		quote                func(string) string
	}{
		{"quoting", "{value}", "'a'\\''b; $(printf data)'", map[string]any{"value": "a'b; $(printf data)"}, shellQuote},
		{"missing", "{missing}:{value}:{missing}", "{missing}:'ok':{missing}", map[string]any{"value": "ok"}, shellQuote},
		{"scalars", "{n}:{flag}:{empty}", "'42':'true':''", map[string]any{"n": 42.0, "flag": true, "empty": nil}, shellQuote},
		{"array", "{values}", "'[80,443]'", map[string]any{"values": []any{80.0, 443.0}}, shellQuote},
		{"http", "https://example.invalid/{a}?v={b}", "https://example.invalid/{b}?v={a}", map[string]any{"a": "{b}", "b": "{a}"}, identity},
		{"literal braces", "prefix {{value}} suffix", "prefix {ok} suffix", map[string]any{"value": "ok"}, identity},
		{"no parameters", "{left}:plain", "{left}:plain", nil, identity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderTemplate(tc.template, tc.params, tc.quote); got != tc.want {
				t.Errorf("rendered %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSecurityTemplateHTTPValuesStayLiteral(t *testing.T) {
	params := map[string]any{"a": "{b}", "b": "{a}"}
	for _, template := range []string{"https://example.invalid/{a}/{b}", "Bearer {a}:{b}", "{\"a\":\"{a}\",\"b\":\"{b}\"}"} {
		want := strings.NewReplacer("{a}", "{b}", "{b}", "{a}").Replace(template)
		if got := renderTemplate(template, params, identity); got != want {
			t.Fatalf("HTTP template recursively expanded values: %q, want %q", got, want)
		}
	}
}
