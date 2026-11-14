package enrich

import (
	"bytes"
	"database/sql"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

type securityRoundTripper func(*http.Request) (*http.Response, error)

func (f securityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSecurityHTTPProbeFailureDoesNotLogURLSecrets(t *testing.T) {
	// sql.Open does not dial; closing the pool makes the real asset-store call
	// fail deterministically at Begin without needing PostgreSQL or a listener.
	conn, err := sql.Open("pgx", "postgres://fixture@localhost/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	const rawURL = "https://fixture-user:password-marker@example.test/?token=query-marker#fragment-marker"
	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })
	requests := 0
	e := &Engine{
		as: (&db.DB{DB: conn}).Assets(),
		client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
			requests++
			if req.URL.String() != rawURL {
				t.Fatalf("probe URL unexpectedly changed: %q", req.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("<title>fixture</title>")),
			}, nil
		})},
	}
	e.doHTTP(47, rawURL)
	if requests != 1 {
		t.Fatalf("expected a successful fake probe before persistence failure, got %d requests", requests)
	}
	got := logs.String()
	for _, secret := range []string{"fixture-user", "password-marker", "query-marker", "fragment-marker", rawURL} {
		if strings.Contains(got, secret) {
			t.Errorf("failure log contains URL secret %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "id=47") || !strings.Contains(got, "sql: database is closed") {
		t.Errorf("failure log must retain asset ID and persistence error: %s", got)
	}
}
