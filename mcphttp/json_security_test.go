package mcphttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMCPJSONResponseCannotBypassStreamLimit(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		wantError      bool
	}{
		{"large result", `{"jsonrpc":"2.0","id":1,"result":"` + strings.Repeat("x", 8<<20) + `"}`, true},
		{"large ignored field", `{"jsonrpc":"2.0","id":1,"result":{},"ignored":"` + strings.Repeat("x", 8<<20) + `"}`, true},
		{"large suffix", `{"jsonrpc":"2.0","id":1,"result":{}}` + strings.Repeat(" ", 8<<20), true},
		{"extra value", `{"jsonrpc":"2.0","id":1,"result":{}} {}`, true},
		{"ordinary response", `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				// Flush first so the large cases exercise unknown/chunked lengths.
				w.(http.Flusher).Flush()
				_, _ = io.WriteString(w, tc.response)
			}))
			defer peer.Close()
			client := &Client{url: peer.URL, http: peer.Client()}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			out, err := client.roundTrip(ctx, rpcRequest{JSONRPC: "2.0", ID: 1, Method: "tools/list"}, true)
			if (err != nil) != tc.wantError {
				t.Fatalf("rejection=%v, want=%v (error=%v)", err != nil, tc.wantError, err)
			}
			if err == nil && (out == nil || out.ID != 1 || string(out.Result) != `{"tools":[]}`) {
				t.Fatalf("normal JSON-RPC response changed: %+v", out)
			}
		})
	}
}
