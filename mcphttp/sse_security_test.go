package mcphttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSSELineAndAggregateEventLimits(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  error
	}{
		{"unterminated-line", "data:" + strings.Repeat("x", maxSSELineBytes), errSSELineTooLarge},
		{"multiline-event", strings.Repeat("data: "+strings.Repeat("x", 65536)+"\n", maxSSEEventBytes/65536+1), errSSEEventTooLarge},
		{"aggregate-overflow-at-EOF", "data: " + strings.Repeat("x", maxSSEEventBytes/2) + "\n" + "data: " + strings.Repeat("y", maxSSEEventBytes/2), errSSEEventTooLarge},
		{"comment-event", strings.Repeat(":"+strings.Repeat("x", 65536)+"\n", maxSSEEventBytes/65536+1), errSSEEventTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readSSEEndpoint(bufio.NewReader(strings.NewReader(test.input)), "http://mcp.test/sse"); !errors.Is(err, test.want) {
				t.Fatalf("endpoint error = %v, want %v", err, test.want)
			}
			if _, err := parseSSE(strings.NewReader(test.input), 1); !errors.Is(err, test.want) {
				t.Fatalf("HTTP SSE error = %v, want %v", err, test.want)
			}
			body := io.NopCloser(strings.NewReader(test.input))
			client := &Client{streamDone: make(chan struct{}), streamErr: make(chan error, 1), streamBody: body, streamCancel: func() {}}
			client.readLegacySSE(bufio.NewReader(body))
			if err := <-client.streamErr; !errors.Is(err, test.want) {
				t.Fatalf("legacy stream error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSSEMultilineAndEOFEvents(t *testing.T) {
	for _, suffix := range []string{"\n\n", ""} {
		input := "event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":7,\"result\":{\"ok\":true}}" + suffix
		response, err := parseSSE(strings.NewReader(input), 7)
		if err != nil || response == nil || string(response.Result) != `{"ok":true}` {
			t.Fatalf("multiline response = %#v, %v", response, err)
		}
	}
	endpoint, err := readSSEEndpoint(bufio.NewReader(strings.NewReader(": ping\n\nevent: endpoint\ndata: /message\n\n")), "http://mcp.test/sse")
	if err != nil || endpoint != "http://mcp.test/message" {
		t.Fatalf("relative endpoint = %q, %v", endpoint, err)
	}
}

func TestNewSSEHandshakeHonorsCallerCancellation(t *testing.T) {
	for _, mode := range []string{"headers", "endpoint"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "endpoint" {
					w.Header().Set("Content-Type", "text/event-stream")
					w.(http.Flusher).Flush()
				}
				close(started)
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			t.Cleanup(func() { close(release); srv.CloseClientConnections(); srv.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				client, err := NewSSE(ctx, "test", srv.URL, nil, false)
				if client != nil {
					_ = client.Close()
				}
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("handshake never reached local server")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("caller cancellation did not stop handshake")
			}
		})
	}
}

func TestNewSSERejectsCrossOriginMessageEndpoint(t *testing.T) {
	var requests atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: endpoint\ndata: %s/message\n\n", other.URL)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := NewSSE(ctx, "test", srv.URL, map[string]string{"X-API-Key": "test-secret"}, false)
	if client != nil {
		_ = client.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "message endpoint") || requests.Load() != 0 {
		t.Fatalf("cross-origin endpoint accepted: err=%v requests=%d", err, requests.Load())
	}
}

func TestSSEEndpointParseErrorDoesNotEchoPayload(t *testing.T) {
	for _, test := range []struct{ name, candidate string }{
		{"invalid-escape", "/private-marker%zz"},
		{"invalid-port", "http://private-marker:bad-port/message"},
		{"near-limit", "/" + strings.Repeat("private-marker", (maxSSELineBytes-128)/len("private-marker")) + "%zz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := readSSEEndpoint(bufio.NewReader(strings.NewReader("data: "+test.candidate+"\n\n")), "http://mcp.test/sse")
			if err == nil {
				t.Fatal("malformed endpoint accepted")
			}
			for cause := err; cause != nil; cause = errors.Unwrap(cause) {
				if len(cause.Error()) > 128 || strings.Contains(cause.Error(), "private-marker") {
					t.Fatalf("endpoint error exposes remote input (length %d)", len(cause.Error()))
				}
			}
		})
	}
}

func TestSSEEndpointRequiresEventSeparator(t *testing.T) {
	for _, suffix := range []string{"", "\n", "\r\n", "\r"} {
		t.Run(fmt.Sprintf("%q", suffix), func(t *testing.T) {
			endpoint, err := readSSEEndpoint(bufio.NewReader(strings.NewReader("event: endpoint\ndata: /message"+suffix)), "http://mcp.test/sse")
			if !errors.Is(err, io.ErrUnexpectedEOF) || endpoint != "" {
				t.Fatalf("truncated endpoint = %q, %v", endpoint, err)
			}
		})
	}
	for _, suffix := range []string{"\n\n", "\r\n\r\n"} {
		endpoint, err := readSSEEndpoint(bufio.NewReader(strings.NewReader("data: /message"+suffix)), "http://mcp.test/sse")
		if err != nil || endpoint != "http://mcp.test/message" {
			t.Fatalf("complete endpoint = %q, %v", endpoint, err)
		}
	}
}

func TestNewSSETruncatedEndpointDoesNotPost(t *testing.T) {
	for _, suffix := range []string{"", "\n", "\r\n"} {
		t.Run(fmt.Sprintf("%q", suffix), func(t *testing.T) {
			var posts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					w.WriteHeader(http.StatusAccepted)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "event: endpoint\ndata: /message"+suffix)
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			client, err := NewSSE(ctx, "test", srv.URL, nil, false)
			if client != nil {
				_ = client.Close()
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) || posts.Load() != 0 {
				t.Fatalf("truncated handshake: err=%v posts=%d", err, posts.Load())
			}
		})
	}
}

// Both response readers intentionally retain EOF acceptance, unlike endpoints.
func TestSSEResponseEOFCompatibility(t *testing.T) {
	for _, suffix := range []string{"", "\n", "\r\n", "\n\n", "\r\n\r\n"} {
		t.Run(fmt.Sprintf("%q", suffix), func(t *testing.T) {
			input := "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}" + suffix
			response, err := parseSSE(strings.NewReader(input), 7)
			if err != nil || response == nil || string(response.Result) != `{"ok":true}` {
				t.Fatalf("HTTP response = %#v, %v", response, err)
			}
			body := io.NopCloser(strings.NewReader(input))
			responses := make(chan *rpcResponse, 1)
			client := &Client{
				streamDone: make(chan struct{}), streamErr: make(chan error, 1),
				streamBody: body, streamCancel: func() {},
				pending: map[int]chan *rpcResponse{7: responses},
			}
			client.readLegacySSE(bufio.NewReader(body))
			select {
			case response := <-responses:
				if string(response.Result) != `{"ok":true}` {
					t.Fatalf("legacy response = %#v", response)
				}
			default:
				t.Fatal("legacy reader discarded final response")
			}
		})
	}
}
