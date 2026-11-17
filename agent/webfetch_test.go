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
	tool := newWebFetch("", "", g)
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
			result := callWebFetch(t, newWebFetch("", "", test.guard), test.ctx, webFetchInput{URL: srv.URL, InsecureSkipVerify: true})
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
	tool := newWebFetch("", "", webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}))
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
	tool := newWebFetch(proxy.URL, "", webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}))
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
	_ = listener.Close()
	recorder, err := traffic.Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	go func() { _ = recorder.Start() }()
	ready := false
	for range 100 {
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
	tool := newWebFetch(recorder.ProxyAddr(), recorder.CACertPath(), webFetchTestGuard([]guard.ScopeRule{{Kind: "ip", Value: "127.0.0.1"}}))
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
	result := callWebFetch(t, newWebFetch(proxy.URL, "", g), ctx, webFetchInput{URL: "http://target.example/page"})
	if !result.IsError || proxyRequests.Load() != 0 {
		t.Fatal("untrusted HTTPS proxy must fail certificate verification")
	}
	tool := newWebFetch(proxy.URL, caFile, g)
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
	tool := newWebFetch("", "", nil)
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
	result := callWebFetch(t, newWebFetch("", "", g), ctx, webFetchInput{URL: srv.URL, InsecureSkipVerify: true})
	if !result.IsError || requests.Load() != 1 || strings.Contains(result.Flatten(), secret) || !strings.Contains(result.Flatten(), "禁止外发") {
		t.Fatalf("redirect egress denial leaked/reached target: %+v requests=%d", result, requests.Load())
	}
	for _, entry := range g.Audit() {
		if strings.Contains(entry.Reason, secret) || strings.Contains(entry.Command, secret) {
			t.Fatalf("redirect secret was written to guard audit: %+v", entry)
		}
	}
}
