package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func commandTemplateFixture(t *testing.T, source string, params map[string]any) actool.Result {
	t.Helper()
	spec, err := json.Marshal(commandExec{Command: source})
	if err != nil {
		t.Fatal(err)
	}
	tool := (&Server{}).buildCustomTool(&db.Tool{Key: "command_quote_fixture", Kind: "command", Exec: spec})
	input, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tool.Call(context.Background(), input, &actool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSecurityCommandTemplateQuoteContexts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("parameterized command tools deliberately reject PowerShell execution")
	}
	backtick := string(rune(0x60))
	values := []struct{ name, value string }{
		{"ordinary", "ordinary value with spaces"},
		{"command substitution", "$(printf SUBSTITUTION_EXECUTED)"},
		{"backtick substitution", backtick + "printf BACKTICK_EXECUTED" + backtick},
		{"quotes and operators", "'\"; printf QUOTE_EXECUTED; #"},
		{"backslashes and variables", "back\\slash\\$UNSET_TEMPLATE_SENTINEL"},
		{"newlines", "line one\nline two\n"},
		{"unicode and placeholders", "你好 {extra} * ? [abc]"},
		{"empty", ""},
	}
	for _, template := range []struct{ name, source, prefix, suffix string }{
		{"unquoted", "printf '<%s>' {args}", "", ""},
		{"double quoted", "printf '<%s>' \"{args}\"", "", ""},
		{"single quoted", "printf '<%s>' '{args}'", "", ""},
		{"unquoted affixes", "printf '<%s>' before:{args}:after", "before:", ":after"},
		{"double quoted affixes", "printf '<%s>' \"before:{args}:after\"", "before:", ":after"},
		{"single quoted affixes", "printf '<%s>' 'before:{args}:after'", "before:", ":after"},
		{"pipeline", "printf '<%s>' \"{args}\" | cat", "", ""},
		{"command sequence", "true &&\nprintf '<%s>' \"{args}\"", "", ""},
	} {
		t.Run(template.name, func(t *testing.T) {
			for _, value := range values {
				t.Run(value.name, func(t *testing.T) {
					result := commandTemplateFixture(t, template.source, map[string]any{
						"args": value.value, "extra": ";printf RECURSIVE_EXECUTED;",
					})
					want := "<" + template.prefix + value.value + template.suffix + ">"
					if result.IsError || result.Flatten() != want {
						t.Fatalf("parameter did not remain literal: value=%q output=%q want=%q", value.value, result.Flatten(), want)
					}
				})
			}
		})
	}
}

func TestSecurityCommandTemplateBackslashContexts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("parameterized command tools deliberately reject PowerShell execution")
	}
	value := "$(printf SUBSTITUTION_EXECUTED)'\"\\"
	for _, tc := range []struct{ source, prefix string }{
		{"printf '<%s>' \\\\{args}", "\\"},
		{"printf '<%s>' \"\\\\{args}\"", "\\"},
		{"printf '<%s>' '\\{args}'", "\\"},
	} {
		result := commandTemplateFixture(t, tc.source, map[string]any{"args": value})
		if result.IsError || result.Flatten() != "<"+tc.prefix+value+">" {
			t.Fatalf("backslash context changed parameter data: source=%q output=%q", tc.source, result.Flatten())
		}
	}
	for _, count := range []int{1, 3, 5} {
		for _, source := range []string{
			"printf '%s' " + strings.Repeat("\\", count) + "{args}",
			"printf '%s' \"" + strings.Repeat("\\", count) + "{args}\"",
		} {
			if _, err := compileCommandTemplate(source, "linux"); err == nil {
				t.Fatalf("unpaired backslash before a placeholder was accepted: %q", source)
			}
		}
	}
}

func unsupportedCommandTemplates() []string {
	backtick := string(rune(0x60))
	return []string{
		"printf '%s' ${args}",
		"printf '%s' ${missing:-{args}}",
		"printf '%s' $(({args}+1))",
		"printf '%s' $(printf '%s' {args})",
		"printf '%s' \"$(printf '%s' '{args}')\"",
		"printf '%s' " + backtick + "printf '%s' {args}" + backtick,
		"cat <(printf '%s' {args})",
		"VALUE={args} printf '%s' safe",
		"VALUE=$(printf '%s' {args}) printf '%s' safe",
		"cat <<EOF\n{args}\nEOF\n",
		"cat <<'EOF'\n{args}\nEOF\n",
		"cat <<EOF\n$(printf '%s' {args})\nEOF\n",
		"cat <<<{args}",
		"printf '%s' safe > {args}",
		"printf '%s' $'{args}'",
		"printf '%s' $\"{args}\"",
		"printf '%s' safe # {args}",
		"(( {args} + 1 ))",
		"[[ {args} == safe ]]",
		"(printf '%s' {args})",
		"{ printf '%s' {args}; }",
		"f() { printf '%s' {args}; }; f",
		"for item in {args}; do printf '%s' \"$item\"; done",
		"printf '%s' \"{args}",
		"printf '%s' $\\\n{args}",
		"printf '%s' \"$\\\n{args}\"",
		"printf '%s' $\\\n\"{args}\"",
		"printf '%s' pre\\\n{args}",
	}
}

func TestSecurityCommandTemplateRejectsUnsupportedAncestors(t *testing.T) {
	for _, source := range unsupportedCommandTemplates() {
		if _, err := compileCommandTemplate(source, "linux"); err == nil {
			t.Errorf("unsupported placeholder context accepted: %q", source)
		}
		// Prefixing a harmless marker ensures a future validation regression
		// cannot execute the initial statement before rejecting the later one.
		result := commandTemplateFixture(t, "printf UNEXPECTED_EXECUTION; "+source, map[string]any{"args": "fixture"})
		if !result.IsError || strings.Contains(result.Flatten(), "UNEXPECTED_EXECUTION") {
			t.Errorf("legacy-row adapter failed to reject before execution: %q output=%q", source, result.Flatten())
		}
	}
}

func TestSecurityCommandTemplateNamesMissingAndStatic(t *testing.T) {
	template, err := compileCommandTemplate("printf '%s' {alpha.name-with-hyphen} {_arg2} {missing}", "linux")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := template.render(map[string]any{"alpha.name-with-hyphen": "{missing}", "_arg2": 42.0, "unused": "$(printf unwanted)"})
	if err != nil || rendered != "printf '%s' '{missing}' '42' {missing}" {
		t.Fatalf("placeholder names or one-pass behavior changed: %q err=%v", rendered, err)
	}
	for _, source := range []string{"Write-Output @('one','two')", "printf 'operator-authored", "echo {1..3}", "printf static\\\ncontinuation"} {
		template, err := compileCommandTemplate(source, "windows")
		if err != nil {
			t.Fatalf("static command was parsed as Bash: %q err=%v", source, err)
		}
		if got, err := template.render(map[string]any{"unused": "anything"}); err != nil || got != source {
			t.Fatalf("static command changed: %q err=%v", got, err)
		}
	}
	if _, err := compileCommandTemplate("Write-Output {args}", "windows"); err == nil || !strings.Contains(err.Error(), "PowerShell") {
		t.Fatalf("parameterized PowerShell execution was not explicitly rejected: %v", err)
	}
	template, err = compileCommandTemplate("printf '%s' \"{args}\"", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := template.render(map[string]any{"args": "prefix\x00suffix"}); err == nil {
		t.Fatal("NUL parameter was accepted")
	}
}

func TestSecurityCommandTemplateHandlersValidateBeforeSQL(t *testing.T) {
	// A non-nil DB with no SQL connection makes accidental persistence/read
	// attempts fail the test. Invalid templates must return before those calls.
	s := &Server{m: &Manager{pg: &db.DB{}}}
	for _, source := range unsupportedCommandTemplates() {
		spec, _ := json.Marshal(commandExec{Command: source})
		body, _ := json.Marshal(customToolReq{Key: "template_fixture", Kind: "command", Exec: spec})
		for _, update := range []bool{false, true} {
			request := httptest.NewRequest(http.MethodPost, "/api/tools/custom", bytes.NewReader(body))
			request.SetPathValue("key", "template_fixture")
			recorder := httptest.NewRecorder()
			if update {
				s.pgUpdateCustomTool(recorder, request)
			} else {
				s.pgCreateCustomTool(recorder, request)
			}
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("invalid template reached persistence: update=%v status=%d", update, recorder.Code)
			}
		}
	}
	for _, spec := range []json.RawMessage{json.RawMessage("{}"), json.RawMessage("{\"command\":false}")} {
		if _, _, err := parseCommandToolExec(spec); err == nil {
			t.Fatalf("invalid execution specification accepted: %s", spec)
		}
	}
	// The unsaved editor uses the runtime guard even without persistence.
	spec, _ := json.Marshal(commandExec{Command: "printf '%s' $'{args}'"})
	body, _ := json.Marshal(testToolReq{Kind: "command", Exec: spec, Params: map[string]any{"args": "fixture"}})
	recorder := httptest.NewRecorder()
	s.pgTestCustomTool(recorder, httptest.NewRequest(http.MethodPost, "/api/tools/custom/test", bytes.NewReader(body)))
	var result map[string]any
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &result) != nil || result["is_error"] != true {
		t.Fatalf("editor bypassed runtime validation: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
