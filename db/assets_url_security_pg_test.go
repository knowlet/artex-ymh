package db

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func openDisposableSchemaDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("ARTEX_AUTH_TEST_DSN")
	if dsn == "" {
		t.Skip("ARTEX_AUTH_TEST_DSN unset; disposable PostgreSQL required for asset URL security regression")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("invalid isolated PostgreSQL configuration: %v", err)
	}
	admin := stdlib.OpenDB(*cfg)
	schema := fmt.Sprintf("asset_url_security_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	d := &DB{DB: stdlib.OpenDB(*cfg)}
	t.Cleanup(func() {
		d.Close()
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		admin.Close()
	})
	if _, err := d.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestSecurityPGHTTPServiceURLSchemeGate proves ValidateAssetURL runs before INSERT.
// The negative-control subtest shows normalizeURL is not a scheme gate (baseline behavior).
func TestSecurityPGHTTPServiceURLSchemeGate(t *testing.T) {
	d := openDisposableSchemaDB(t)
	av := d.Assets()

	t.Run("negative_control_normalizeURL_leaves_javascript", func(t *testing.T) {
		n := normalizeURL("javascript:alert(1)")
		if !strings.HasPrefix(strings.ToLower(n), "javascript:") {
			t.Fatalf("control: normalizeURL altered or stripped javascript scheme: %q", n)
		}
	})

	for _, malicious := range []string{
		"javascript:alert(1)",
		"ftp://evil.example.test/",
		"https://exa mple.test/",
		"https://example.test/\tpath",
		"https://example.test/\x00path",
		" https://example.test/",
		"https://exam\u00a0ple.test/",
		"https://:443/path",
	} {
		t.Run("reject_"+malicious, func(t *testing.T) {
			_, err := av.UpsertHTTPService(UpsertHTTPServiceReq{URL: malicious})
			if err == nil {
				t.Fatal("expected validation error before write")
			}
			var count int
			if err := d.QueryRow(`SELECT count(*) FROM assets`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("dangerous URL row persisted: %d", count)
			}
		})
	}

	const spa = "https://spa-frag.example.test/#/dashboard"
	id, err := av.UpsertHTTPService(UpsertHTTPServiceReq{URL: spa})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, id) })
	var stored, domain, serviceName string
	var port int
	if err := d.QueryRow(`SELECT url, domain, port, service_name FROM assets WHERE id=$1`, id).Scan(&stored, &domain, &port, &serviceName); err != nil {
		t.Fatal(err)
	}
	if stored != spa {
		t.Fatalf("fragment must survive storage without server rewrite: stored=%q", stored)
	}
	if domain != "spa-frag.example.test" || port != 443 || serviceName != "HTTPS" {
		t.Fatalf("valid URL lost derived metadata: domain=%q port=%d service=%q", domain, port, serviceName)
	}
	id2, err := av.UpsertHTTPService(UpsertHTTPServiceReq{URL: spa})
	if err != nil || id2 != id {
		t.Fatalf("dedup broken after validation-only path: id1=%d id2=%d err=%v", id, id2, err)
	}
}

func TestSecurityPGArchiveRestoreSkipsInvalidHTTPServiceURL(t *testing.T) {
	d := openDisposableSchemaDB(t)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	raw := json.RawMessage(`[{
		"id": 424242,
		"type": "service",
		"service_type": "http",
		"url": "javascript:alert(1)",
		"domain": "evil.example.test",
		"port": 443,
		"service_name": "HTTPS"
	}]`)
	mapping, warnings, err := restoreArchiveAssets(tx, 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	if mapped, ok := mapping[424242]; !ok || mapped != 0 {
		t.Fatalf("malicious archived asset should be marked skipped: %+v", mapping)
	}
	ok := false
	for _, w := range warnings {
		if strings.Contains(w, "跳过") {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatalf("expected skip warning, got %#v", warnings)
	}
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM assets WHERE id=424242`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("javascript URL must not be inserted via archive restore")
	}
}
