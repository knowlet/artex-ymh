package context1337

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

type toolRoundTripper func(*http.Request) (*http.Response, error)

func (fn toolRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func toolTestClient(t *testing.T, transport toolRoundTripper) *Client {
	t.Helper()
	client, err := NewClient("https://operator.invalid", "synthetic-read-key")
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = transport
	return client
}

func toolResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func toolOutput(t *testing.T, result actool.Result, err error) map[string]any {
	t.Helper()
	if err != nil || result.IsError || len(result.Extra) != 0 {
		t.Fatalf("unexpected tool error or extra action: %+v, %v", result, err)
	}
	var output map[string]any
	if err := json.Unmarshal([]byte(result.Flatten()), &output); err != nil {
		t.Fatalf("tool did not return structured metadata: %v", err)
	}
	if output["provider"] != "context1337" || output["target_vulnerability"] != "unverified" || output["evidence_kind"] != "external_cve_metadata" {
		t.Fatalf("missing external-reference boundary: %v", output)
	}
	return output
}

func TestToolRequiresLiveAuthorization(t *testing.T) {
	var requests, authorized atomic.Int64
	client := toolTestClient(t, func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return toolResponse(http.StatusOK, `{"query_applied":true,"total":0,"items":[]}`), nil
	})
	for name, tool := range map[string]actool.CoreTool{
		"catalog":            Tool(nil, nil),
		"missing client":     Tool(nil, func(context.Context) bool { authorized.Add(1); return true }),
		"missing authorizer": Tool(client, nil),
		"revoked":            Tool(client, func(context.Context) bool { authorized.Add(1); return false }),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := tool.Call(t.Context(), json.RawMessage(`{"cve":"CVE-2999-1234"}`), nil)
			if err != nil || !result.IsError || len(result.Extra) != 0 {
				t.Fatalf("unauthorized lookup not denied: %+v, %v", result, err)
			}
		})
	}
	if requests.Load() != 0 || authorized.Load() != 1 {
		t.Fatalf("unauthorized client used: requests=%d authorizations=%d", requests.Load(), authorized.Load())
	}
}

func TestToolRejectsNoncanonicalInputBeforeAuthorizationOrNetwork(t *testing.T) {
	var requests, authorized atomic.Int64
	client := toolTestClient(t, func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return toolResponse(http.StatusOK, `{"query_applied":true,"total":0,"items":[]}`), nil
	})
	tool := Tool(client, func(context.Context) bool { authorized.Add(1); return true })
	for _, input := range []string{
		``, `null`, `[]`, `{}`, `{"CVE":"CVE-2999-1234"}`,
		`{"cve":null}`, `{"cve":1234}`, `{"cve":["CVE-2999-1234"]}`,
		`{"cve":"cve-2999-1234"}`, `{"cve":"CVE-2999-123"}`, `{"cve":" CVE-2999-1234"}`,
		`{"cve":"CVE-2999-1234 target.invalid"}`,
		`{"cve":"CVE-2999-1234","source":null}`, `{"cve":"CVE-2999-1234","source":{}}`,
		`{"cve":"CVE-2999-1234","source":""}`,
		`{"cve":"CVE-2999-1234","source":"team"}`, `{"cve":"CVE-2999-1234","Source":"builtin"}`,
		`{"cve":"CVE-2999-1234","cve":"CVE-2999-5678"}`,
		`{"cve":"CVE-2999-1234","\u0063ve":"CVE-2999-5678"}`,
		`{"cve":"CVE-2999-1234","source":"builtin","source":"nuclei"}`,
		`{"cve":"CVE-2999-1234","target":"https://target.invalid"}`,
		`{"cve":"CVE-2999-1234","endpoint":"https://other.invalid"}`,
		`{"cve":"CVE-2999-1234","api_key":"replacement"}`,
		`{"cve":"CVE-2999-1234"} {}`, `{"cve":"CVE-2999-1234",}`,
		`{"cve":"CVE-2999-1234"}` + strings.Repeat(" ", 513),
		"{\"cve\":\"CVE-2999-1234\",\"source\":\"" + string([]byte{0xff}) + "\"}",
	} {
		result, err := tool.Call(t.Context(), json.RawMessage(input), nil)
		if err != nil || !result.IsError || len(result.Extra) != 0 {
			t.Fatalf("invalid input accepted: %q: %+v, %v", input, result, err)
		}
		if strings.Contains(result.Flatten(), "target.invalid") || strings.Contains(result.Flatten(), "replacement") {
			t.Fatal("rejected input was echoed")
		}
	}
	if requests.Load() != 0 || authorized.Load() != 0 {
		t.Fatalf("invalid input reached authorization/network: %d/%d", authorized.Load(), requests.Load())
	}
	// The declared byte boundary is inclusive for otherwise valid input.
	input := `{"cve":"CVE-2999-1234"}`
	result, err := tool.Call(t.Context(), json.RawMessage(input+strings.Repeat(" ", 512-len(input))), nil)
	if output := toolOutput(t, result, err); output["status"] != "no_exact_match_in_bounded_page" {
		t.Fatalf("valid boundary input failed: %v", output)
	}
	result, err = tool.Call(t.Context(), json.RawMessage(input+strings.Repeat(" ", 513-len(input))), nil)
	if err != nil || !result.IsError || requests.Load() != 1 || authorized.Load() != 1 {
		t.Fatalf("input byte boundary failed: %+v, %v", result, err)
	}
}

func TestToolReturnsMetadataWithoutRemoteInstructionsOrActions(t *testing.T) {
	for _, source := range []string{"builtin", "nuclei"} {
		t.Run(source, func(t *testing.T) {
			var requests, authorized int
			client := toolTestClient(t, func(r *http.Request) (*http.Response, error) {
				requests++
				if r.Method != http.MethodGet || r.URL.Host != "operator.invalid" || r.URL.Path != "/api/resources" ||
					r.URL.RawQuery != "enabled=true&limit=20&offset=0&q=CVE-2999-1234&source="+source+"&type=vuln" || r.ContentLength != 0 {
					t.Errorf("unexpected request shape: %s %s", r.Method, r.URL)
				}
				return toolResponse(http.StatusOK, `{"query_applied":true,"total":1,"instructions":"injected-direction-marker","items":[{"type":"vuln","name":"CVE-2999-1234","source":"`+source+`","enabled":true,"description":"injected-description-marker","content":"injected-content-marker","payload":"injected-payload-marker","dictionary":"injected-dictionary-marker","url":"https://untrusted.invalid/execute","tool_calls":[{"name":"report_finding"}]}]}`), nil
			})
			tool := Tool(client, func(context.Context) bool { authorized++; return true })
			input := json.RawMessage(`{"cve":"CVE-2999-1234","source":"` + source + `"}`)
			result, err := tool.Call(t.Context(), input, nil)
			output := toolOutput(t, result, err)
			if output["status"] != "metadata_match" || output["source"] != source || requests != 1 || authorized != 1 {
				t.Fatalf("unexpected lookup lifecycle: %v, requests=%d authorizations=%d", output, requests, authorized)
			}
			matches, ok := output["matches"].([]any)
			if !ok || len(matches) != 1 || matches[0].(map[string]any)["resource_id"] != "absec://"+source+"/vuln/CVE-2999-1234" {
				t.Fatalf("missing canonical metadata reference: %v", matches)
			}
			for _, forbidden := range []string{"injected-", "untrusted.invalid", "tool_calls", "report_finding", "synthetic-read-key", "operator.invalid"} {
				if strings.Contains(result.Flatten(), forbidden) {
					t.Fatalf("remote instruction, endpoint or secret escaped metadata projection: %s", forbidden)
				}
			}
			if !tool.IsReadOnly(input) || !tool.IsConcurrencySafe(input) {
				t.Fatal("metadata tool lost read-only/concurrency classification")
			}
		})
	}
}

func TestToolProviderFailureDoesNotFailExercise(t *testing.T) {
	for name, transport := range map[string]toolRoundTripper{
		"unavailable": func(*http.Request) (*http.Response, error) {
			return toolResponse(http.StatusServiceUnavailable, "remote-secret-body"), nil
		},
		"timeout": func(*http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		},
		"transport": func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport-secret-detail")
		},
		"malformed": func(*http.Request) (*http.Response, error) {
			return toolResponse(http.StatusOK, "remote-secret-invalid-json"), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			tool := Tool(toolTestClient(t, transport), func(context.Context) bool { return true })
			result, err := tool.Call(t.Context(), json.RawMessage(`{"cve":"CVE-2999-1234"}`), nil)
			if output := toolOutput(t, result, err); output["status"] != "metadata_unavailable" || output["source"] != "builtin" {
				t.Fatalf("provider failure changed task semantics: %v", output)
			}
			if strings.Contains(result.Flatten(), "secret") || strings.Contains(result.Flatten(), "operator.invalid") {
				t.Fatal("provider failure leaked remote detail")
			}
		})
	}
}

func TestToolInflightCancellationProducesNoResult(t *testing.T) {
	started := make(chan struct{})
	client := toolTestClient(t, func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	tool := Tool(client, func(context.Context) bool { return true })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	var result actool.Result
	var err error
	go func() {
		result, err = tool.Call(ctx, json.RawMessage(`{"cve":"CVE-2999-1234"}`), nil)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("metadata request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("metadata request ignored task cancellation")
	}
	if !errors.Is(err, context.Canceled) || result.Flatten() != "" || len(result.Extra) != 0 {
		t.Fatalf("cancellation returned metadata: %+v, %v", result, err)
	}
}

func TestToolRequestDeadlineIsBounded(t *testing.T) {
	var remaining time.Duration
	client := toolTestClient(t, func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Error("exercise request has no deadline")
			return nil, errors.New("missing deadline")
		}
		remaining = time.Until(deadline)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	tool := Tool(client, func(context.Context) bool { return true })
	started := time.Now()
	result, err := tool.Call(t.Context(), json.RawMessage(`{"cve":"CVE-2999-1234"}`), nil)
	if output := toolOutput(t, result, err); output["status"] != "metadata_unavailable" {
		t.Fatalf("provider timeout failed task: %v", output)
	}
	if remaining <= 0 || remaining > 3*time.Second || time.Since(started) > 5*time.Second {
		t.Fatalf("exercise lookup exceeded deadline: remaining=%s elapsed=%s", remaining, time.Since(started))
	}
}

func TestToolConcurrencyBoundIsSharedAndReleasesOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{}, 8)
	var authorizations atomic.Int64
	client := toolTestClient(t, func(r *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	authorize := func(context.Context) bool { authorizations.Add(1); return true }
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			// Separate tool instances must still share the same bound.
			result, err := Tool(client, authorize).Call(ctx, json.RawMessage(`{"cve":"CVE-2999-1234"}`), nil)
			if !errors.Is(err, context.Canceled) || result.Flatten() != "" {
				t.Errorf("active lookup did not cancel cleanly: %+v %v", result, err)
			}
		})
	}
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			cancel()
			wg.Wait()
			t.Fatal("four bounded requests did not start")
		}
	}
	waitCtx, stopWaiting := context.WithTimeout(t.Context(), 100*time.Millisecond)
	result, err := Tool(client, authorize).Call(waitCtx, json.RawMessage(`{"cve":"CVE-2999-1234"}`), nil)
	stopWaiting()
	if !errors.Is(err, context.DeadlineExceeded) || result.Flatten() != "" || authorizations.Load() != 4 {
		cancel()
		wg.Wait()
		t.Fatalf("queued lookup exceeded shared concurrency bound: auth=%d result=%+v err=%v", authorizations.Load(), result, err)
	}
	cancel()
	wg.Wait()
	// A later call succeeds only if canceled requests released all held slots.
	client = toolTestClient(t, func(*http.Request) (*http.Response, error) {
		return toolResponse(http.StatusOK, `{"query_applied":true,"total":0,"items":[]}`), nil
	})
	result, err = Tool(client, authorize).Call(t.Context(), json.RawMessage(`{"cve":"CVE-2999-1234"}`), nil)
	if output := toolOutput(t, result, err); output["status"] != "no_exact_match_in_bounded_page" {
		t.Fatalf("canceled lookup retained concurrency slot: %v", output)
	}
}
