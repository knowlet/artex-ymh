package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/traffic"
	actool "github.com/Autumn-27/norma/tool"
)

func webFetchTestGuard(rules []guard.ScopeRule) *guard.Guard {
	g := guard.New()
	g.SetRoE(guard.RoEConfig{
		Mode:     func() string { return "warn" }, // exception gate must remain strict
		Scope:    func(int64) []guard.ScopeRule { return rules },
		TaskIDOf: func(ctx context.Context) int64 { return RunInfoFrom(ctx).TaskID },
	})
	return g
}

func callWebFetch(t *testing.T, tool actool.CoreTool, ctx context.Context, input webFetchInput) actool.Result {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tool.Call(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// The certificate is self-signed and has DNS SANs only. This reproduces the
// reported IP-SAN mismatch rather than merely trusting httptest's usual cert.
func webFetchNoIPSANServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.invalid"},
		DNSNames: []string{"test.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestWebFetchScopedTLSOptIn(t *testing.T) {
	var requests atomic.Int32
	srv := webFetchNoIPSANServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<h1>fixture</h1><p>reachable</p>")
	}))
	ctx := WithRunInfo(t.Context(), RunInfo{TaskID: 42})
	g := webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}})
	tool := newWebFetch("", "", g, nil)
	strict := callWebFetch(t, tool, ctx, webFetchInput{URL: srv.URL})
	if !strict.IsError || !strings.Contains(strict.Flatten(), "IP SAN") || requests.Load() != 0 {
		t.Fatalf("default must reject invalid IP certificate: %+v requests=%d", strict, requests.Load())
	}
	optIn := callWebFetch(t, tool, ctx, webFetchInput{URL: srv.URL, InsecureSkipVerify: true})
	if optIn.IsError || !strings.Contains(optIn.Flatten(), "# fixture") || !strings.Contains(optIn.Flatten(), "not captured") || requests.Load() != 1 {
		t.Fatalf("explicit scoped opt-in should fetch fixture: %+v requests=%d", optIn, requests.Load())
	}
	strict = callWebFetch(t, tool, ctx, webFetchInput{URL: srv.URL})
	if !strict.IsError || requests.Load() != 1 {
		t.Fatal("TLS exception leaked into the next strict call")
	}
	for _, test := range []struct {
		name  string
		ctx   context.Context
		guard *guard.Guard
	}{
		{"no guard", ctx, nil},
		{"unscoped chat", t.Context(), g},
		{"unregistered scope", ctx, webFetchTestGuard(nil)},
		{"local exemption is insufficient", ctx, webFetchTestGuard([]guard.ScopeRule{{Kind: "domain", Value: "target.example"}})},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := callWebFetch(t, newWebFetch("", "", test.guard, nil), test.ctx, webFetchInput{URL: srv.URL, InsecureSkipVerify: true})
			if !result.IsError || requests.Load() != 1 {
				t.Fatalf("unscoped exception reached target: %+v requests=%d", result, requests.Load())
			}
		})
	}
}

func TestWebFetchTLSRedirectScope(t *testing.T) {
	var requests atomic.Int32
	var redirectURL string
	srv := webFetchNoIPSANServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "completed")
	}))
	ctx := WithRunInfo(t.Context(), RunInfo{TaskID: 42})
	tool := newWebFetch("", "", webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}), nil)
	for _, test := range []struct {
		name        string
		destination string
		allowed     bool
	}{
		{"same authorized host", srv.URL + "/done", true},
		{"outside registered scope", strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/done", false},
		{"TLS downgrade", strings.Replace(srv.URL, "https://", "http://", 1) + "/done", false},
		{"userinfo", strings.Replace(srv.URL, "https://", "https://user@", 1) + "/done", false},
		{"static asset", srv.URL + "/bundle.js", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			redirectURL = test.destination
			before := requests.Load()
			result := callWebFetch(t, tool, ctx, webFetchInput{URL: srv.URL, InsecureSkipVerify: true})
			wantRequests := int32(1)
			if test.allowed {
				wantRequests = 2
			}
			if result.IsError == test.allowed || requests.Load()-before != wantRequests {
				t.Fatalf("redirect authorization: result=%+v target requests=%d", result, requests.Load()-before)
			}
		})
	}
}

func TestWebFetchProxyRequiresExplicitDirectException(t *testing.T) {
	var targetRequests, proxyRequests atomic.Int32
	target := webFetchNoIPSANServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		_, _ = io.WriteString(w, "direct fixture")
	}))
	// A failed CONNECT models a recording proxy rejecting untrusted upstream TLS.
	// It must not silently cause a direct retry, as Norma's built-in did.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyRequests.Add(1)
		http.Error(w, "upstream certificate verification failed", http.StatusBadGateway)
	}))
	defer proxy.Close()
	ctx := WithRunInfo(t.Context(), RunInfo{TaskID: 42})
	tool := newWebFetch(proxy.URL, "", webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}), nil)
	result := callWebFetch(t, tool, ctx, webFetchInput{URL: target.URL})
	if !result.IsError || proxyRequests.Load() != 1 || targetRequests.Load() != 0 {
		t.Fatalf("strict proxy route changed: %+v proxy=%d target=%d", result, proxyRequests.Load(), targetRequests.Load())
	}
	for _, input := range []webFetchInput{
		{URL: target.URL, InsecureSkipVerify: true},
		{URL: target.URL, Direct: true},
	} {
		result = callWebFetch(t, tool, ctx, input)
		if !result.IsError || proxyRequests.Load() != 1 || targetRequests.Load() != 0 {
			t.Fatalf("partial opt-in changed route: %+v", result)
		}
	}
	result = callWebFetch(t, tool, ctx, webFetchInput{URL: target.URL, InsecureSkipVerify: true, Direct: true})
	if result.IsError || !strings.Contains(result.Flatten(), "direct fixture") || proxyRequests.Load() != 1 || targetRequests.Load() != 1 {
		t.Fatalf("explicit direct TLS exception failed: %+v proxy=%d target=%d", result, proxyRequests.Load(), targetRequests.Load())
	}
	result = callWebFetch(t, tool, ctx, webFetchInput{URL: target.URL})
	if !result.IsError || proxyRequests.Load() != 2 || targetRequests.Load() != 1 {
		t.Fatal("explicit direct call changed the later default route")
	}
}

func TestWebFetchRecordingProxyTLSException(t *testing.T) {
	t.Setenv("ARTEX_PROXY_AUTH", "off")
	t.Setenv("ARTEX_PROXY_SSL_INSECURE", "false")
	var targetRequests atomic.Int32
	target := webFetchNoIPSANServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		_, _ = io.WriteString(w, "recording-proxy-test-target")
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	recorder, err := traffic.Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	var startError error
	startDone := make(chan struct{})
	go func() {
		startError = recorder.Start()
		close(startDone)
	}()
	t.Cleanup(func() {
		if err := recorder.Close(); err != nil {
			t.Errorf("closing recording proxy: %v", err)
		}
		select {
		case <-startDone:
			if startError != nil && !errors.Is(startError, http.ErrServerClosed) {
				t.Errorf("recording proxy Start failed: %v", startError)
			}
		case <-time.After(time.Second):
			t.Error("recording proxy Start did not return after Close")
		}
	})
	ready := false
	for range 100 {
		select {
		case <-startDone:
			t.Fatalf("recording proxy stopped before ready: %v", startError)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("recording proxy did not start")
	}
	ctx, cancel := context.WithTimeout(WithRunInfo(t.Context(), RunInfo{TaskID: 42}), 5*time.Second)
	defer cancel()
	tool := newWebFetch(recorder.ProxyAddr(), recorder.CACertPath(), webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}), nil)
	strict := callWebFetch(t, tool, ctx, webFetchInput{URL: target.URL})
	if targetRequests.Load() != 0 || strings.Contains(strict.Flatten(), "recording-proxy-test-target") {
		t.Fatalf("trusting recorder CA unexpectedly disabled upstream verification: %+v", strict)
	}
	missingDirect := callWebFetch(t, tool, ctx, webFetchInput{URL: target.URL, InsecureSkipVerify: true})
	if !missingDirect.IsError || targetRequests.Load() != 0 || !strings.Contains(missingDirect.Flatten(), "direct=true") {
		t.Fatalf("proxy route was bypassed implicitly: %+v", missingDirect)
	}
	optIn := callWebFetch(t, tool, ctx, webFetchInput{URL: target.URL, InsecureSkipVerify: true, Direct: true})
	if optIn.IsError || targetRequests.Load() != 1 || !strings.Contains(optIn.Flatten(), "recording-proxy-test-target") || !strings.Contains(optIn.Flatten(), "not captured") {
		t.Fatalf("explicit per-call exception failed behind configured recorder: %+v", optIn)
	}
}

func TestWebFetchScopedDNSDial(t *testing.T) {
	ctx := WithRunInfo(t.Context(), RunInfo{TaskID: 42})
	for _, test := range []struct {
		name    string
		ips     []string
		extra   []guard.ScopeRule
		allowed bool
	}{
		{"public domain address", []string{"203.0.113.9"}, nil, true},
		{"private domain address", []string{"192.168.50.10"}, nil, true},
		{"loopback alias blocked", []string{"127.0.0.1"}, nil, false},
		{"linklocal alias blocked", []string{"169.254.169.254"}, nil, false},
		{"IPv6 loopback alias blocked", []string{"::1"}, nil, false},
		{"IPv6 linklocal alias blocked", []string{"fe80::1"}, nil, false},
		{"mixed public local snapshot blocked", []string{"203.0.113.9", "127.0.0.1"}, nil, false},
		{"explicitly scoped local alias", []string{"127.0.0.1"}, []guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := webFetchTestGuard(append([]guard.ScopeRule{{Kind: "domain", Value: "target.example"}}, test.extra...))
			lookups, dials := 0, 0
			var dialed string
			dial := webFetchScopedDialContext(g, func(_ context.Context, host string) ([]net.IPAddr, error) {
				lookups++
				if host != "target.example" {
					t.Fatalf("lookup host=%q", host)
				}
				if lookups > 1 {
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				}
				var addresses []net.IPAddr
				for _, ip := range test.ips {
					addresses = append(addresses, net.IPAddr{IP: net.ParseIP(ip)})
				}
				return addresses, nil
			}, func(_ context.Context, network, address string) (net.Conn, error) {
				dials++
				dialed = address
				if network != "tcp" {
					t.Fatalf("dial network=%q", network)
				}
				host, _, err := net.SplitHostPort(address)
				if err != nil || net.ParseIP(host) == nil {
					t.Fatalf("dial must receive pinned numeric IP: %q", address)
				}
				left, right := net.Pipe()
				_ = right.Close()
				return left, nil
			})
			conn, err := dial(ctx, "tcp", "target.example:443")
			if conn != nil {
				_ = conn.Close()
			}
			if (err == nil) != test.allowed || lookups != 1 || (test.allowed && (dials != 1 || dialed != net.JoinHostPort(test.ips[0], "443"))) || (!test.allowed && dials != 0) {
				t.Fatalf("allowed=%v error=%v lookups=%d dials=%d address=%s", test.allowed, err, lookups, dials, dialed)
			}
		})
	}
	// A failed candidate uses only the originally validated DNS snapshot, not a
	// second lookup that could return an unauthorized local address.
	lookups, dials := 0, 0
	g := webFetchTestGuard([]guard.ScopeRule{{Kind: "domain", Value: "target.example"}})
	dial := webFetchScopedDialContext(g, func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}, {IP: net.ParseIP("203.0.113.10")}}, nil
	}, func(_ context.Context, _ string, address string) (net.Conn, error) {
		dials++
		if address != fmt.Sprintf("203.0.113.%d:443", 8+dials) {
			t.Fatalf("unexpected fallback address: %s", address)
		}
		return nil, errors.New("fixture connection refused")
	})
	if _, err := dial(ctx, "tcp", "target.example:443"); err == nil || lookups != 1 || dials != 2 {
		t.Fatalf("fallback resolved again: error=%v lookup=%d dial=%d", err, lookups, dials)
	}
}

func TestWebFetchLocalHostnameRequiresIPScope(t *testing.T) {
	var requests atomic.Int32
	srv := webFetchNoIPSANServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "local target")
	}))
	ctx := WithRunInfo(t.Context(), RunInfo{TaskID: 42})
	input := webFetchInput{URL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), InsecureSkipVerify: true, Direct: true}
	for _, allowed := range []bool{false, true} {
		rules := []guard.ScopeRule{{Kind: "domain", Value: "localhost"}}
		if allowed {
			rules = append(rules, guard.ScopeRule{Kind: "cidr", Value: "127.0.0.0/8"}, guard.ScopeRule{Kind: "ip", Value: "::1"})
		}
		before := requests.Load()
		result := callWebFetch(t, newWebFetch("", "", webFetchTestGuard(rules), nil), ctx, input)
		if result.IsError == allowed || (allowed && requests.Load() != before+1) || (!allowed && requests.Load() != before) {
			t.Fatalf("local hostname scope failed: allowed=%v result=%+v requests=%d", allowed, result, requests.Load()-before)
		}
	}
}

func TestWebFetchUsesTaskUserAgent(t *testing.T) {
	const wantUA = "Mozilla/5.0 WebFetch-task-UA-fixture"
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	uaFn := func(taskID int64) string {
		if taskID == 42 {
			return wantUA
		}
		return ""
	}
	g := webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}})
	result := callWebFetch(t, newWebFetch("", "", g, uaFn), WithRunInfo(t.Context(), RunInfo{TaskID: 42}), webFetchInput{URL: srv.URL})
	if result.IsError || gotUA != wantUA {
		t.Fatalf("task UA not used: result=%+v gotUA=%q", result, gotUA)
	}
	if strings.Contains(gotUA, "norma/") {
		t.Fatalf("framework UA leaked: %q", gotUA)
	}
}

func TestWebFetchMalformedRedirectDoesNotLeakSecret(t *testing.T) {
	const secret = "synthetic-malformed-location-secret"
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "https://"+secret+".example/%zz")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	g := webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}})
	egress := guard.NewEgressGuard()
	egress.AddFingerprint("test", secret)
	g.SetEgress(egress)
	result := callWebFetch(t, newWebFetch("", "", g, nil), WithRunInfo(t.Context(), RunInfo{TaskID: 42}), webFetchInput{URL: srv.URL})
	if !result.IsError || requests.Load() != 1 || strings.Contains(result.Flatten(), secret) || !strings.Contains(result.Flatten(), "invalid redirect Location header") {
		t.Fatalf("malformed Location leaked: %+v requests=%d", result, requests.Load())
	}
	for _, entry := range g.Audit() {
		if strings.Contains(entry.Reason, secret) || strings.Contains(entry.Command, secret) {
			t.Fatalf("malformed Location leaked to audit: %+v", entry)
		}
	}
}

func TestWebFetchStrictTLSDowngrade(t *testing.T) {
	var insecureRequests atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		insecureRequests.Add(1)
		_, _ = io.WriteString(w, "plain fixture")
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, plain.URL, http.StatusFound) }))
	defer secure.Close()
	caFile := filepath.Join(t.TempDir(), "target-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	tool := newWebFetch("", caFile, nil, nil)
	result := callWebFetch(t, tool, t.Context(), webFetchInput{URL: secure.URL})
	if !result.IsError || insecureRequests.Load() != 0 || !strings.Contains(result.Flatten(), "HTTPS to an insecure scheme") {
		t.Fatalf("strict HTTPS downgraded: %+v requests=%d", result, insecureRequests.Load())
	}
	result = callWebFetch(t, tool, t.Context(), webFetchInput{URL: plain.URL})
	if result.IsError || insecureRequests.Load() != 1 {
		t.Fatalf("initial HTTP should remain supported: %+v", result)
	}
}

func TestWebFetchRawResponseLimitReported(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprintf("extra-%d", extra), func(t *testing.T) {
			prefix := "<p>visible</p><script>"
			body := prefix + strings.Repeat(" ", maxWebFetchResponseBytes+extra-len(prefix))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Server", strings.Repeat("s", 4000))
				w.Header().Set("X-Powered-By", strings.Repeat("p", 4000))
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			result := callWebFetch(t, newWebFetch("", "", nil, nil), t.Context(), webFetchInput{URL: srv.URL + "/" + strings.Repeat("a", 4000)})
			if result.IsError || !strings.Contains(result.Flatten(), "visible") || strings.Contains(result.Flatten(), "body truncated at 2 MiB") != (extra > 0) || len(result.Flatten()) > 50000 {
				t.Fatalf("raw body cutoff not represented: %+v", result)
			}
		})
	}
}

func TestWebFetchProxyCATrustAndRedirectGuard(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://outside.example/destination", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "forwarded fixture")
	}))
	defer proxy.Close()
	proxy.Config.ErrorLog = log.New(io.Discard, "", 0)
	caFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	g := webFetchTestGuard([]guard.ScopeRule{{Kind: "domain", Value: "target.example"}})
	g.SetRoE(guard.RoEConfig{Mode: func() string { return "strict" }, Scope: func(int64) []guard.ScopeRule { return []guard.ScopeRule{{Kind: "domain", Value: "target.example"}} }, TaskIDOf: func(context.Context) int64 { return 42 }})
	ctx := WithRunInfo(t.Context(), RunInfo{TaskID: 42})
	result := callWebFetch(t, newWebFetch(proxy.URL, "", g, nil), ctx, webFetchInput{URL: "http://target.example/page"})
	if !result.IsError || proxyRequests.Load() != 0 {
		t.Fatal("untrusted HTTPS proxy must fail certificate verification")
	}
	tool := newWebFetch(proxy.URL, caFile, g, nil)
	result = callWebFetch(t, tool, ctx, webFetchInput{URL: "http://target.example/page"})
	if result.IsError || !strings.Contains(result.Flatten(), "forwarded fixture") || proxyRequests.Load() != 1 {
		t.Fatalf("configured proxy CA not trusted: %+v", result)
	}
	result = callWebFetch(t, tool, ctx, webFetchInput{URL: "http://target.example/redirect"})
	if !result.IsError || !strings.Contains(result.Flatten(), "RoE") || proxyRequests.Load() != 2 {
		t.Fatalf("normal redirect escaped common guard: %+v proxy requests=%d", result, proxyRequests.Load())
	}
}

func TestWebFetchContentAndSchema(t *testing.T) {
	tool := newWebFetch("", "", nil, nil)
	properties := tool.InputSchema()["properties"].(map[string]any)
	for _, name := range []string{"url", "extract", "insecure_skip_verify", "direct"} {
		if properties[name] == nil {
			t.Fatalf("missing WebFetch schema parameter %s", name)
		}
	}
	html := `<title>Title</title><h2>Section</h2><p>Hello <b>world</b>.</p><script src="/app.js"></script><script>const p = "/api/test";</script><!-- test note --><form method="post" action="/login"><input name="csrf" type="hidden" value="fixture"></form><meta name="generator" content="fixture"><a href="/next">next</a>`
	plain := webFetchContent([]byte(html), "text/html; charset=utf-8", false)
	if !strings.Contains(plain, "## Section") || !strings.Contains(plain, "**world**") || strings.Contains(plain, "test note") || strings.Contains(plain, "const p") {
		t.Fatalf("Markdown content lost or script/comment rendered: %s", plain)
	}
	extracted := webFetchContent([]byte(html), "text/html", true)
	for _, want := range []string{"=== RECON ===", "test note", "/app.js", "/api/test", "POST /login", "csrf(hidden=fixture)", "generator=fixture", "[next](/next)"} {
		if !strings.Contains(extracted, want) {
			t.Errorf("extract missing %q: %s", want, extracted)
		}
	}
	if got := webFetchContent([]byte(`{"ok":true}`), "application/json", true); got != `{"ok":true}` {
		t.Fatalf("API response changed: %q", got)
	}
	if got := limitWebFetchText("中中中", 5); !utf8.ValidString(got) || !strings.Contains(got, "truncated") {
		t.Fatalf("truncated output is invalid UTF-8: %q", got)
	}
	for _, path := range []string{"https://target.example/a.JS?q=1", "https://target.example/a.css"} {
		u, _ := url.Parse(path)
		if !webFetchStaticAsset(u) {
			t.Fatalf("static asset allowed: %s", path)
		}
	}
}

func TestWebFetchRedirectEgressDoesNotLeakSecret(t *testing.T) {
	const secret = "synthetic-redirect-secret"
	var requests atomic.Int32
	srv := webFetchNoIPSANServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "https://"+secret+".example/", http.StatusFound)
	}))
	g := webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}, {Kind: "domain", Value: "example"}})
	egress := guard.NewEgressGuard()
	egress.AddFingerprint("test", secret)
	g.SetEgress(egress)
	ctx := WithRunInfo(t.Context(), RunInfo{TaskID: 42})
	result := callWebFetch(t, newWebFetch("", "", g, nil), ctx, webFetchInput{URL: srv.URL, InsecureSkipVerify: true})
	if !result.IsError || requests.Load() != 1 || strings.Contains(result.Flatten(), secret) || !strings.Contains(result.Flatten(), "禁止外发") {
		t.Fatalf("redirect egress denial leaked/reached target: %+v requests=%d", result, requests.Load())
	}
	for _, entry := range g.Audit() {
		if strings.Contains(entry.Reason, secret) || strings.Contains(entry.Command, secret) {
			t.Fatalf("redirect secret was written to guard audit: %+v", entry)
		}
	}
}
