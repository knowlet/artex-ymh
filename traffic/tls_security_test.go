package traffic

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecordingProxyTLSVerificationAndOptIn(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		name := "verified-default"
		if insecure {
			name = "self-signed-opt-in"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("ARTEX_PROXY_AUTH", "off")
			t.Setenv("ARTEX_PROXY_SSL_INSECURE", "")
			if insecure {
				t.Setenv("ARTEX_PROXY_SSL_INSECURE", "true")
			}
			var requests atomic.Int32
			backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte("target"))
			}))
			defer backend.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := listener.Addr().String()
			_ = listener.Close()
			root := t.TempDir()
			tr, err := Open(root, addr)
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = tr.Start() }()
			defer tr.Close()
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
				t.Fatal("local recording proxy did not start")
			}
			ca, err := newStealthCA(filepath.Join(root, "_ca"))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca.cert)
			proxyURL, _ := url.Parse(tr.ProxyAddr())
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := client.Get(strings.Replace(backend.URL, "127.0.0.1", "localhost", 1))
			var body []byte
			if response != nil {
				body, _ = io.ReadAll(response.Body)
				_ = response.Body.Close()
			}
			if insecure {
				if err != nil || response == nil || response.StatusCode != http.StatusOK || string(body) != "target" || requests.Load() != 1 {
					t.Fatalf("explicit self-signed opt-in failed: response=%v error=%v body=%q requests=%d", response, err, body, requests.Load())
				}
			} else if requests.Load() != 0 || (response != nil && response.StatusCode == http.StatusOK) {
				t.Fatalf("default proxy accepted untrusted target TLS: error=%v requests=%d", err, requests.Load())
			}
		})
	}
}
