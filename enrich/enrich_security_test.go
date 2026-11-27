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
	// sql.Open does not dial. The closed pool lets a credential-free URL reach
	// a deterministic persistence error without PostgreSQL or a listener; legacy
	// userinfo must now fail validation before that database access.
	conn, err := sql.Open("pgx", "postgres://fixture@localhost/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		rawURL    string
		wantError string
	}{
		{
			name:      "legacy_userinfo_validation",
			rawURL:    "https://fixture-user:password-marker@example.test/?token=query-marker#fragment-marker",
			wantError: "资产 URL 不可嵌入凭据",
		},
		{
			name:      "database_persistence",
			rawURL:    "https://example.test/?token=query-marker#fragment-marker",
			wantError: "sql: database is closed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			previousWriter := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previousWriter) })
			requests := 0
			e := &Engine{
				as: (&db.DB{DB: conn}).Assets(),
				client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
					requests++
					if req.URL.String() != tc.rawURL {
						t.Fatalf("probe URL unexpectedly changed: %q", req.URL.String())
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("<title>fixture</title>")),
					}, nil
				})},
			}
			e.doHTTP(47, tc.rawURL)
			if requests != 1 {
				t.Fatalf("expected a successful fake probe before asset update failure, got %d requests", requests)
			}
			got := logs.String()
			for _, secret := range []string{"fixture-user", "password-marker", "query-marker", "fragment-marker", tc.rawURL} {
				if strings.Contains(got, secret) {
					t.Errorf("failure log contains URL secret %q: %s", secret, got)
				}
			}
			if !strings.Contains(got, "id=47") || !strings.Contains(got, tc.wantError) {
				t.Errorf("failure log must retain asset ID and expected error %q: %s", tc.wantError, got)
			}
		})
	}
}
