package agent

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProviderClientDoesNotForwardAPIKeyAcrossOrigins(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHits.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, source.URL, nil)
	req.Header.Set("X-API-Key", "synthetic-key")
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || targetHits.Load() != 0 {
		t.Fatal("LLM client forwarded API key to a different origin")
	}
}
