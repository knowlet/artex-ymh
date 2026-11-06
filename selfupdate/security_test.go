package selfupdate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type updateTestTransport func(*http.Request) (*http.Response, error)

func (f updateTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type endlessUpdateBody struct {
	read   int
	closed bool
}

func (b *endlessUpdateBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read += len(p)
	return len(p), nil
}
func (b *endlessUpdateBody) Close() error { b.closed = true; return nil }

func updateClientWithBody(body io.ReadCloser) *http.Client {
	return &http.Client{Transport: updateTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: r}, nil
	})}
}

func TestDownloadCapsStreamAndRemovesPartialFile(t *testing.T) {
	for _, declared := range []int64{0, 128} {
		t.Run(fmt.Sprint(declared), func(t *testing.T) {
			body := &endlessUpdateBody{}
			dst := filepath.Join(t.TempDir(), "release.zip.part")
			asset := Asset{Name: "release.zip", URL: "https://github.com/example/release.zip", Size: declared}
			var err error
			if declared == 0 {
				// Exercise unknown-length streaming with a small fixture budget;
				// production uses the hard maxReleaseAssetSize budget.
				_, err = downloadBounded(t.Context(), updateClientWithBody(body), asset, dst, nil, 128)
			} else {
				_, err = download(t.Context(), updateClientWithBody(body), asset, dst, nil)
			}
			if err == nil || body.read != 129 || !body.closed {
				t.Fatalf("unbounded transfer: err=%v read=%d closed=%v", err, body.read, body.closed)
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Fatalf("failed transfer left partial file: %v", err)
			}
		})
	}
}

func TestDownloadMetadataRejectedBeforeRequest(t *testing.T) {
	client := &http.Client{Transport: updateTestTransport(func(*http.Request) (*http.Response, error) {
		t.Error("invalid metadata reached transport")
		return nil, errors.New("unexpected request")
	})}
	for _, size := range []int64{-1, maxReleaseAssetSize + 1} {
		if _, err := download(t.Context(), client, Asset{Size: size}, filepath.Join(t.TempDir(), "partial"), nil); err == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
	if limit, err := assetDownloadLimit(Asset{}); err != nil || limit != maxReleaseAssetSize {
		t.Fatalf("unknown-size limit = %d, %v", limit, err)
	}
}

func TestDownloadExactSizeAndTruncation(t *testing.T) {
	for _, size := range []int64{0, 7, 8} {
		dst := filepath.Join(t.TempDir(), "partial")
		asset := Asset{Name: "release.zip", URL: "https://github.com/example/release.zip", Size: size}
		sum, err := download(context.Background(), updateClientWithBody(io.NopCloser(strings.NewReader("payload"))), asset, dst, nil)
		if size == 8 {
			if err == nil {
				t.Fatal("truncated asset accepted")
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Fatalf("truncated file retained: %v", err)
			}
			continue
		}
		if err != nil || sum != fmt.Sprintf("%x", sha256.Sum256([]byte("payload"))) || readAll(t, dst) != "payload" {
			t.Fatalf("valid download = %q, %v", sum, err)
		}
	}
}

func TestConcurrentRollbacksPreserveBothVersions(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "current-v2", 0)
	fakeBin(t, p.Old, "previous-v1", 0)
	current, old := readAll(t, p.Current), readAll(t, p.Old)
	if err := os.WriteFile(p.Current+".swap", []byte("unrelated retained file"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { <-start; results <- rollbackPaths(p) })
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if readAll(t, p.Current) != current || readAll(t, p.Old) != old {
		t.Fatal("concurrent reversible swaps lost a version")
	}
	if readAll(t, p.Current+".swap") != "unrelated retained file" {
		t.Fatal("removed another operation's temporary file")
	}
	if leftovers, err := filepath.Glob(filepath.Join(p.Dir, ".artex-rollback-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("successful rollback left temporary directories: %v, %v", leftovers, err)
	}
}

func TestSettlePreservesNewlyStagedMarker(t *testing.T) {
	p := testPaths(t)
	if err := os.WriteFile(p.New, []byte("pending binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(p.Marker, marker{From: "1", To: "2"}); err != nil {
		t.Fatal(err)
	}
	settle(p)
	if m, ok := readMarker(p.Marker); !ok || m.To != "2" {
		t.Fatal("settle erased the pending update marker")
	}
}
