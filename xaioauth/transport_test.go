package xaioauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTransportInjectsCurrentBearerPreservesStreamAndCaller(t *testing.T) {
	m := testManager(t)
	saveFixture(t, m, time.Now().Add(time.Hour))
	body := `{"model":"grok-4.6","stream":true,"input":"hello"}`
	req, _ := http.NewRequest(http.MethodPost, APIBaseURL+"/responses", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer placeholder")
	stream := io.NopCloser(strings.NewReader("data: event-one\n\ndata: event-two\n\n"))
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer fixture-access" {
			t.Fatal("did not inject OAuth bearer")
		}
		data, _ := io.ReadAll(r.Body)
		if string(data) != body {
			t.Fatal("changed Responses payload")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: stream}, nil
	})
	resp, err := m.Transport(base).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != stream || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("stream was buffered or replaced")
	}
	if req.Header.Get("Authorization") != "Bearer placeholder" {
		t.Fatal("mutated caller's headers")
	}
	resp.Body.Close()
}

func TestTransport401RefreshesAndReplaysExactlyOnce(t *testing.T) {
	for _, secondStatus := range []int{200, 401, 403} {
		t.Run(http.StatusText(secondStatus), func(t *testing.T) {
			m := testManager(t)
			saveFixture(t, m, time.Now().Add(time.Hour))
			var authCalls, apiCalls int
			m.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				authCalls++
				if req.URL.String() != tokenEndpoint {
					t.Fatal("wrong auth endpoint")
				}
				return jsonResponse(200, validTokenJSON), nil
			})
			payload := `{"input":"hello","model":"grok-4.6"}`
			base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				apiCalls++
				data, _ := io.ReadAll(req.Body)
				if string(data) != payload {
					t.Error("request body not replayed")
				}
				want := "Bearer fixture-access"
				if apiCalls == 2 {
					want = "Bearer fixture-access-new"
				}
				if req.Header.Get("Authorization") != want {
					t.Error("wrong bearer generation")
				}
				if apiCalls == 1 {
					return jsonResponse(401, `{"error":"fixture-access is invalid"}`), nil
				}
				return jsonResponse(secondStatus, `{"detail":"fixture-access-new"}`), nil
			})
			req, _ := http.NewRequest(http.MethodPost, APIBaseURL+"/responses", strings.NewReader(payload))
			resp, err := m.Transport(base).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if authCalls != 1 || apiCalls != 2 || resp.StatusCode != secondStatus {
				t.Fatalf("calls auth=%d api=%d status=%d", authCalls, apiCalls, resp.StatusCode)
			}
			data, _ := io.ReadAll(resp.Body)
			if secondStatus != 200 && strings.Contains(string(data), "fixture-access") {
				t.Fatal("authentication failure echoed bearer")
			}
			if secondStatus == 403 && !strings.Contains(string(data), "entitlement") {
				t.Fatal("missing subscription entitlement guidance")
			}
		})
	}
}

func TestTransport403DoesNotRefresh(t *testing.T) {
	m := testManager(t)
	saveFixture(t, m, time.Now().Add(time.Hour))
	req, _ := http.NewRequest(http.MethodGet, APIBaseURL+"/models", nil)
	resp, err := m.Transport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(403, `{"message":"secret response"}`), nil
	})).RoundTrip(req)
	if err != nil || resp.StatusCode != 403 {
		t.Fatal(resp, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(data), "secret response") {
		t.Fatal("raw authorization body escaped")
	}
}

func TestTransportNonReplayable401DoesNotRotate(t *testing.T) {
	m := testManager(t)
	saveFixture(t, m, time.Now().Add(time.Hour))
	calls := 0
	req, _ := http.NewRequest(http.MethodPost, APIBaseURL+"/responses", io.NopCloser(strings.NewReader("not-replayable")))
	resp, err := m.Transport(roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return jsonResponse(401, `{}`), nil })).RoundTrip(req)
	if err != nil || resp.StatusCode != 401 || calls != 1 {
		t.Fatal(resp, err, calls)
	}
	resp.Body.Close()
}

func TestTransportBlocksRedirectsAndUnsafeDestinationsBeforeAuth(t *testing.T) {
	for _, endpoint := range []string{"http://api.x.ai/v1/responses", "https://api.x.ai.evil.test/v1/responses", "https://evil.test/v1/responses", "https://api.x.ai:444/v1/responses", "https://api.x.ai/v1/chat/completions", "https://api.x.ai/v1/responses?redirect=evil", "https://api.x.ai/v1/%72esponses", "https://user:pass@api.x.ai/v1/responses"} {
		t.Run(endpoint, func(t *testing.T) {
			m := testManager(t)
			base := roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("unsafe request reached transport")
				return nil, nil
			})
			req, _ := http.NewRequest(http.MethodPost, endpoint, nil)
			if _, err := m.Transport(base).RoundTrip(req); !errors.Is(err, ErrUnsafeEndpoint) {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("same-origin-redirect", func(t *testing.T) {
		m := testManager(t)
		saveFixture(t, m, time.Now().Add(time.Hour))
		calls := 0
		client := &http.Client{Transport: m.Transport(roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			r := jsonResponse(307, "")
			r.Header.Set("Location", APIBaseURL+"/models")
			return r, nil
		}))}
		_, err := client.Get(APIBaseURL + "/models")
		if err == nil || calls != 1 {
			t.Fatal("redirect followed", calls, err)
		}
	})
	t.Run("no-token-no-request", func(t *testing.T) {
		m := testManager(t)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, APIBaseURL+"/models", nil)
		if _, err := m.Transport(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("request without token"); return nil, nil })).RoundTrip(req); !errors.Is(err, ErrNotConnected) {
			t.Fatal(err)
		}
	})
}

func TestTransportStrictRequestShape(t *testing.T) {
	for _, req := range []*http.Request{nil, {Method: http.MethodGet}, {Method: http.MethodDelete, URL: &url.URL{Scheme: "https", Host: "api.x.ai", Path: "/v1/models"}}} {
		if validInferenceRequest(req) {
			t.Fatal("unsafe request shape accepted")
		}
	}
}
