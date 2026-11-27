package db

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityAssetURLDisplayPreservesKeysAndMasksUserinfo(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://fixture-user:fixture-secret@example.test/path?q=1#frag", "https://REDACTED@example.test/path?q=1#frag"},
		{"https://fixture-user@example.test/", "https://REDACTED@example.test/"},
		{"https://@example.test/", "https://REDACTED@example.test/"},
		{"https://fixture-user:fixture%2Dsecret@[2001:db8::1]:8443/", "https://REDACTED@[2001:db8::1]:8443/"},
		{"https://fixture-user:fixture%ZZsecret@example.test/", "[invalid asset URL]"},
		{"https:fixture-user:fixture-secret@example.test/path", "[invalid asset URL]"},
		{"https:/fixture-user:fixture-secret@example.test/path", "[invalid asset URL]"},
		{"/fixture-user:fixture-secret@example.test/path", "[invalid asset URL]"},
		{"ftp://fixture-user:fixture-secret@example.test/path", "[invalid asset URL]"},
		{"https://example.test/user@example.test?q=a@b#c@d", "https://example.test/user@example.test?q=a@b#c@d"},
		{"https://Example.TEST:443/a%20b?q=two%20words#frag", "https://Example.TEST:443/a%20b?q=two%20words#frag"},
		{"192.0.2.1:443", "192.0.2.1:443"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			if got := AssetURLForDisplay(tc.raw); got != tc.want {
				t.Fatalf("display URL = %q, want %q", got, tc.want)
			}
			asset := Asset{ID: 42, Type: "service", URL: tc.raw, Domain: "example.test"}
			blob, err := json.Marshal(&asset)
			if err != nil {
				t.Fatal(err)
			}
			var view struct {
				ID                     int64  `json:"id"`
				Type                   string `json:"type"`
				Domain                 string `json:"domain"`
				URL                    string `json:"url"`
				URLCredentialsRedacted bool   `json:"url_credentials_redacted"`
			}
			if err := json.Unmarshal(blob, &view); err != nil {
				t.Fatal(err)
			}
			if view.ID != 42 || view.Type != "service" || view.Domain != "example.test" || view.URL != tc.want || view.URLCredentialsRedacted != (tc.raw != tc.want) {
				t.Fatalf("unexpected asset JSON: %s", blob)
			}
			if asset.URL != tc.raw {
				t.Fatal("display serialization changed execution URL or natural key")
			}
		})
	}
}

func TestSecurityAssetDisplayLabelsMaskUserinfo(t *testing.T) {
	const raw = "https://fixture-user:fixture-secret@example.test/path"
	const want = "https://REDACTED@example.test/path"
	checks := map[string]string{
		"coverage":     coverageNodeLabel(&CoverageGraphNode{Kind: "service", URL: raw}),
		"finding tree": (&assetRow{kind: "endpoint", url: raw}).label(),
		"notification": assetDisplayName("endpoint", "", "", raw, "", ""),
		"mention":      assetURLLabelForDisplay("GET " + raw),
		"intercept":    (&Asset{ID: 42, Type: "endpoint", URL: raw}).InterceptLabel(),
	}
	for name, label := range checks {
		if strings.Contains(label, "fixture-") || !strings.Contains(label, want) {
			t.Errorf("%s exposes credentials or loses target: %q", name, label)
		}
	}
}

func TestSecurityPGAssetURLLegacyDisplayRedaction(t *testing.T) {
	d := openDisposableSchemaDB(t)
	store := d.Assets()
	task, err := d.CreateTaskWithOptions("legacy asset display", "display only", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Userinfo extends beyond the old mention-label truncation boundary. It must
	// be redacted before truncation or its prefix can escape parser detection.
	raw := "https://fixture-user:" + strings.Repeat("fixture-secret", 20) + "@legacy.example.test/path"
	ids := []int64{}
	for _, typ := range []string{"service", "endpoint"} {
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,service_type,url,method,domain,root_domain,task_ids,honeypot_score)
VALUES($1,'http',$2,'GET','legacy.example.test','example.test',ARRAY[$3::bigint],0.75) RETURNING id`, typ, raw, task.ID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := store.AddAutoScope(task.ID, "service", "", raw, ""); err != nil {
		t.Fatal(err)
	}
	intent, err := d.Exploration(task.ExplorationID).AddNode(KindIntent, map[string]any{"summary": "legacy asset fixture"}, 1, "open", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if err := d.Exploration(task.ExplorationID).Anchor(intent, id); err != nil {
			t.Fatal(err)
		}
	}
	assertProjection := func(name string, value any, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		blob, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(blob), "fixture-") || !strings.Contains(string(blob), "REDACTED@legacy.example.test") {
			t.Fatalf("%s did not redact legacy credentials: %s", name, blob)
		}
	}
	assets, err := store.GetByIDs(ids)
	assertProjection("asset JSON", assets, err)
	if len(assets) != 2 || assets[0].URL != raw || assets[1].URL != raw {
		t.Fatal("reading asset JSON must leave execution URLs unchanged")
	}
	graph, err := store.BuildCoverageGraph(task.ID, task.ExplorationID)
	assertProjection("coverage graph", graph, err)
	backlog, count, err := store.ListUntestedAssets(task.ID, task.ExplorationID, "", 10, 0)
	assertProjection("backlog", backlog, err)
	if count != 2 {
		t.Fatalf("backlog count=%d, want both legacy assets", count)
	}
	backlog, count, err = store.ListUntestedAssetsWithSources(task.ID, "", 10, 0)
	assertProjection("source backlog", backlog, err)
	if count != 2 {
		t.Fatalf("source backlog count=%d, want both legacy assets", count)
	}
	intents, err := store.IntentAssets(task.ID)
	assertProjection("intent labels", intents, err)
	mentions, err := d.SearchChatMentions(t.Context(), "asset", "legacy.example.test")
	assertProjection("mentions before truncation", mentions, err)
	labels, err := d.NotificationAssetNames(t.Context(), ids)
	assertProjection("notification labels", labels, err)
	honeypots, err := store.HoneypotAssetsByTask(task.ID, 10)
	assertProjection("honeypot labels", honeypots, err)
	for _, id := range ids {
		var stored string
		if err := d.QueryRow(`SELECT url FROM assets WHERE id=$1`, id).Scan(&stored); err != nil || stored != raw {
			t.Fatalf("legacy stored key was modified: %q, %v", stored, err)
		}
	}
}
