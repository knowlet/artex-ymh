package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReproductionMarkdownBacktickFence(t *testing.T) {
	raw := json.RawMessage(`{"steps":[{"request":"GET /x HTTP/1.1\n\n` + "```" + `oops","response":"ok"}]}`)
	out := ReproductionMarkdown(raw)
	if !strings.Contains(out, "````http\n") {
		t.Fatalf("expected 4+ backtick fence for request, got:\n%s", out)
	}
	if !strings.Contains(out, "oops") {
		t.Fatalf("body not preserved in output:\n%s", out)
	}
}

func TestReproductionMarkdown(t *testing.T) {
	raw := json.RawMessage(`{
		"entry_point": "POST /login",
		"prerequisites": ["测试账号"],
		"steps": [{
			"request": "POST /login HTTP/1.1\n\n{}",
			"response": "HTTP/1.1 200 OK",
			"expected": "200",
			"proves": "登录成功",
			"exchange_id": "ex-1"
		}],
		"provenance": "worker intent 42"
	}`)
	out := ReproductionMarkdown(raw)
	for _, want := range []string{"入口点", "前置条件", "步骤 1", "ex-1", "POST /login"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
