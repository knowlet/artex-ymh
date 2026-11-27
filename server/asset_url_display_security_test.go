package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSecurityFindingAssetLabelMasksURLCredentials(t *testing.T) {
	asset := &db.Asset{URL: "https://fixture-user:fixture-secret@example.test/path", Method: "GET"}
	if got := assetLabel(asset); got != "GET https://REDACTED@example.test/path" {
		t.Fatalf("finding asset label = %q", got)
	}
}
