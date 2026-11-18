package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
)

func TestTransientModelErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.New("openai: status 504: <html>nginx</html>"), true},
		{errors.New("HTTP status=503 overloaded"), true},
		{errors.New("status 408"), true},
		{errors.New("status 429: rate limit exceeded"), true},
		{fmt.Errorf("stream: %w", io.ErrUnexpectedEOF), true},
		{io.EOF, true},
		{errors.New("temporary network error"), true},
		{errors.New("dial tcp: connection reset by peer"), true},
		{errors.New("anthropic: overloaded_error"), true},
		{&CallTimeoutError{}, true},
		{&ResponseIdleTimeoutError{}, true},
		{context.Canceled, false},
		{errors.New("status 429: insufficient_quota"), false},
		{errors.New("status 400: invalid request"), false},
		{errors.New("status 401: timeout reading secret"), false},
		{errors.New("HTTP 403"), false},
		{errors.New("status 413"), false},
		{errors.New("status 422"), false},
		{errors.New("litellm.ContextWindowExceededError"), false},
		{errors.New("status 502: Context_Window_Exceeded"), false},
		{errors.New("context length exceeded"), false},
		{errors.New("unparsed_dsml_tool_call"), false},
		{errors.New("invalid tool call arguments"), false},
		{errors.New("unknown provider error"), false},
		{nil, false},
	} {
		if got := IsTransientModelError(tc.err); got != tc.want {
			t.Errorf("IsTransientModelError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestProviderContextOverflowAliasReachesCompactor(t *testing.T) {
	// Real Norma OpenAI paths, not just matching a helper's output. An API body
	// containing only the exception class previously missed reactive compaction.
	t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "0")
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":{"message":"litellm.ContextWindowExceededError"}}`)
			}))
			defer srv.Close()
			cfg := ConfigFrom("openai", "fixture", srv.URL, "fixture-key", "")
			cfg.Retry.ConnectAttempts = -1
			p, err := cfg.NewProvider()
			if err != nil {
				t.Fatal(err)
			}
			req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("fixture")}}
			if stream {
				for _, e := range p.Stream(context.Background(), req) {
					if e != nil {
						err = e
					}
				}
			} else {
				_, _, _, err = p.Complete(context.Background(), req)
			}
			if !compaction.IsOverflow(err) || IsTransientModelError(err) {
				t.Fatalf("error must compact, not replay unchanged: %v", err)
			}
			if errors.Unwrap(err) == nil {
				t.Fatalf("original provider error was lost: %v", err)
			}
		})
	}
}
