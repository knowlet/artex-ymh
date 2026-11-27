package db

import (
	"encoding/json"
	"net/url"
	"strings"
)

// AssetURLForDisplay masks all URL userinfo, including usernames, in legacy
// assets. Keep a visible marker instead of silently turning an authenticated
// target into an unauthenticated one. This is a display projection only: never
// use it to rewrite natural keys, credentials, or archived traffic evidence.
func AssetURLForDisplay(raw string) string {
	if !strings.Contains(raw, "@") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Hostname() == "" ||
		(!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
		// A malformed legacy URL may contain credentials that Parse cannot
		// separate reliably, including successful parses as opaque/relative
		// URLs. Do not include that input in an error or label.
		return "[invalid asset URL]"
	}
	if u.User == nil {
		return raw // @ in a path, query, or fragment is not URL userinfo.
	}
	u.User = url.User("REDACTED")
	return u.String()
}

// MarshalJSON protects API and list_assets output without changing the in-memory
// URL used by host matching or existing execution paths. Raw archive snapshots
// use their original database rows, not this presentation projection.
func (a Asset) MarshalJSON() ([]byte, error) {
	type assetFields Asset
	view := assetFields(a)
	view.URL = AssetURLForDisplay(a.URL)
	return json.Marshal(struct {
		assetFields
		URLCredentialsRedacted bool `json:"url_credentials_redacted,omitempty"`
	}{view, view.URL != a.URL})
}

// assetURLLabelForDisplay also handles endpoint mention labels prefixed by an
// HTTP method. Call before truncating labels: truncation can hide the trailing
// @ and make a credential prefix look like an ordinary path.
func assetURLLabelForDisplay(label string) string {
	if scheme := strings.Index(label, "://"); scheme >= 0 {
		if space := strings.LastIndexByte(label[:scheme], ' '); space >= 0 {
			return label[:space+1] + AssetURLForDisplay(label[space+1:])
		}
	}
	return AssetURLForDisplay(label)
}
