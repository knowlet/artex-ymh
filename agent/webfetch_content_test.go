package agent

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestWebFetchDeclaredHTMLCharsets(t *testing.T) {
	for _, test := range []struct {
		name, contentType, declaration, text string
		encoding                             encoding.Encoding
	}{
		{"GBK header", "text/html; charset=GBK", "", "中文测试", simplifiedchinese.GBK},
		{"Shift JIS header", "text/html; charset=Shift_JIS", "", "日本語テスト", japanese.ShiftJIS},
		{"Shift JIS meta", "text/html", `<meta charset="Shift_JIS">`, "日本語テスト", japanese.ShiftJIS},
		{"UTF-8 detection", "text/html", "", "繁體中文測試", encoding.Nop},
	} {
		t.Run(test.name, func(t *testing.T) {
			html := test.declaration + "<title>" + test.text + "</title><p>" + test.text + "</p>" +
				"<!-- " + test.text + " --><form action=\"/login\"><input name=\"message\" type=\"hidden\" value=\"" + test.text + "\"></form>"
			body, err := test.encoding.NewEncoder().Bytes([]byte(html))
			if err != nil {
				t.Fatal(err)
			}
			result := webFetchContent(body, test.contentType, true)
			if !utf8.ValidString(result) {
				t.Fatalf("response did not become UTF-8: %q", result)
			}
			for _, want := range []string{"# " + test.text, "## COMMENTS\n- " + test.text, "message(hidden=" + test.text + ")"} {
				if !strings.Contains(result, want) {
					t.Errorf("decoded text or RECON lost %q: %s", want, result)
				}
			}
		})
	}
}

func TestWebFetchReconSurvivesOutputLimit(t *testing.T) {
	var html strings.Builder
	html.WriteString("<h1>Page start</h1><p>" + strings.Repeat("測試內容 ", 20000) + "</p>")
	// Fill each section enough that preserving RECON also requires a separate
	// bound. A large comments section must not erase later forms/meta/links.
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&html, "<!-- comment-%d %s -->", i, strings.Repeat("測", 300))
		fmt.Fprintf(&html, `<script src="/script-%d.js"></script><script>const p = "/endpoint-%d";</script>`, i, i)
		fmt.Fprintf(&html, `<form action="/form-%d" method="post"><input type="hidden" name="fixture" value="%s"></form>`, i, strings.Repeat("測", 300))
		fmt.Fprintf(&html, `<meta name="meta-%d" content="%s"><a href="/link-%d">link</a>`, i, strings.Repeat("測", 300), i)
	}
	const header = "[200 OK] https://fixture.invalid/\n[Body truncated at input limit.]\n"
	result := webFetchOutput(header, []byte(html.String()), "text/html; charset=utf-8", true)
	if len(result) > webFetchOutputBytes || !utf8.ValidString(result) {
		t.Fatalf("output cap/UTF-8 violated: bytes=%d valid=%v", len(result), utf8.ValidString(result))
	}
	for _, want := range []string{
		header, "# Page start", "[truncated]", "=== RECON ===",
		"## COMMENTS", "comment-0", "## SCRIPTS (src)", "/script-0.js",
		"## INLINE ENDPOINTS", "/endpoint-0", "## FORMS", "POST /form-0",
		"## META", "meta-0=", "## LINKS", "/link-0",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("large page lost %q", want)
		}
	}
	if start := strings.Index(result, "\n\n=== RECON ==="); start < 0 || len(result[start:]) > webFetchReconBytes {
		t.Fatalf("RECON is absent or exceeds its own budget: start=%d total=%d", start, len(result))
	}
	withoutRecon := webFetchOutput(header, []byte(html.String()), "text/html; charset=utf-8", false)
	if strings.Contains(withoutRecon, "=== RECON ===") || len(withoutRecon) > webFetchOutputBytes || !utf8.ValidString(withoutRecon) {
		t.Fatal("extract=false changed or violated the output bound")
	}
	// Exercise the actual tool caller too: an outer cap applied after joining
	// an unbounded page would still erase RECON even if a helper test passed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, html.String())
	}))
	defer srv.Close()
	fetched := callWebFetch(t, newWebFetch("", "", nil), t.Context(), webFetchInput{URL: srv.URL, Extract: true})
	if fetched.IsError || len(fetched.Flatten()) > webFetchOutputBytes || !strings.Contains(fetched.Flatten(), "=== RECON ===") || !strings.Contains(fetched.Flatten(), "POST /form-0") {
		t.Fatalf("tool caller discarded bounded RECON: error=%v bytes=%d", fetched.IsError, len(fetched.Flatten()))
	}
}

func TestWebFetchContentOutputBudget(t *testing.T) {
	// Long metadata must leave space for the requested content, and every byte
	// cap includes its marker. The real caller also bounds individual fields.
	header := "[200 OK] fixture\n" + strings.Repeat("伺服器", 2000)
	body := []byte(`<!-- fixture-recon --><p>` + strings.Repeat("測試", 30000) + "</p>")
	result := webFetchOutput(header, body, "text/html; charset=utf-8", true)
	if len(result) > webFetchOutputBytes || !utf8.ValidString(result) || !strings.Contains(result, "fixture-recon") {
		t.Fatalf("metadata crowded out bounded RECON: len=%d valid=%v", len(result), utf8.ValidString(result))
	}
	const apiBody = `{"message":"繁體中文"}`
	if got := webFetchOutput("", []byte(apiBody), "application/json", true); got != apiBody {
		t.Fatalf("small API response changed: %q", got)
	}
	for _, budget := range []int{0, 1, 2, 5, 11, 12, 13, 50, 1024} {
		got := webFetchContentWithBudget(body, "text/html; charset=utf-8", true, budget)
		if len(got) > budget || !utf8.ValidString(got) {
			t.Fatalf("budget=%d produced len=%d valid=%v", budget, len(got), utf8.ValidString(got))
		}
	}
}
