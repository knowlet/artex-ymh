package db

import (
	"strings"
	"testing"
)

func TestSecurityPGAssetURLCredentialsAndEndpointGate(t *testing.T) {
	d := openDisposableSchemaDB(t)
	store := d.Assets()
	for _, typ := range []string{"service", "endpoint"} {
		for _, raw := range []string{
			"https://fixture-user:fixture-secret@credentials.example.test/path",
			"https://fixture-user@credentials.example.test/path",
			"https://:fixture-secret@credentials.example.test/path",
			"https://@credentials.example.test/path",
			"https://fixture-user:fixture%2Dsecret@[2001:db8::1]:8443/path",
			"javascript:alert(1)",
			"ftp://credentials.example.test/path",
			"relative/path",
			"https:///path",
			"https://credentials.example.test/a b",
			"https://credentials.example.test/\x00path",
		} {
			t.Run(typ+"/"+raw, func(t *testing.T) {
				var id int64
				var err error
				if typ == "service" {
					id, err = store.UpsertHTTPService(UpsertHTTPServiceReq{URL: raw, IP: "192.0.2.42", TaskID: 123})
				} else {
					id, err = store.UpsertEndpoint(UpsertEndpointReq{URL: raw, Method: "GET", IP: "192.0.2.42", TaskID: 123})
				}
				if err == nil || id != 0 {
					t.Fatalf("unsafe URL accepted: id=%d error=%v", id, err)
				}
				if strings.Contains(err.Error(), "fixture-") {
					t.Errorf("validation error discloses URL credentials: %v", err)
				}
				var count int
				if err := d.QueryRow(`SELECT count(*) FROM assets`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("rejected URL wrote assets or derived host/IP rows: %d", count)
				}
			})
		}
	}

	// Explicit service auth remains supported; no credential extraction or
	// silent change to natural keys is needed to accept a credential-free URL.
	const serviceURL = "https://credentials.example.test/"
	id, err := store.UpsertHTTPService(UpsertHTTPServiceReq{
		URL:  serviceURL,
		Auth: []map[string]any{{"type": "basic", "username": "fixture-user", "password": "fixture-secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assets, err := store.GetByIDs([]int64{id})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read service: assets=%v error=%v", assets, err)
	}
	if assets[0].URL != "https://credentials.example.test" || len(assets[0].Auth) != 1 || assets[0].Auth[0]["password"] != "fixture-secret" {
		t.Fatalf("explicit auth or ordinary root normalization changed: %+v", assets[0])
	}

	const endpointURL = "https://credentials.example.test:8443/a%20b?q=user@example.test#fragment"
	endpointID, err := store.UpsertEndpoint(UpsertEndpointReq{URL: endpointURL, Method: "get"})
	if err != nil {
		t.Fatal(err)
	}
	assets, err = store.GetByIDs([]int64{endpointID})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read endpoint: assets=%v error=%v", assets, err)
	}
	asset := assets[0]
	if asset.URL != endpointURL || asset.Domain != "credentials.example.test" || asset.Port == nil || *asset.Port != 8443 || asset.Method != "GET" {
		t.Fatalf("valid endpoint URL or derived metadata changed: %+v", asset)
	}
	duplicateID, err := store.UpsertEndpoint(UpsertEndpointReq{URL: endpointURL, Method: "GET"})
	if err != nil || duplicateID != endpointID {
		t.Fatalf("endpoint dedup changed: first=%d duplicate=%d error=%v", endpointID, duplicateID, err)
	}
}
