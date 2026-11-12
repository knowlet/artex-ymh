package db

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityArchiveRejectsUnsafeURLBeforeLookup(t *testing.T) {
	for _, rawURL := range []string{"javascript:alert(1)", "data:text/html,fixture", "", "https://bad host.example/"} {
		t.Run(rawURL, func(t *testing.T) {
			raw, err := json.Marshal([]map[string]any{{
				"id": 42, "type": "service", "service_type": "http", "url": rawURL,
			}})
			if err != nil {
				t.Fatal(err)
			}
			// Rejection must precede all database access, including reuse of an
			// existing natural-key match. A nil transaction proves that ordering.
			mapping, warnings, err := restoreArchiveAssets(nil, 1, raw)
			if err != nil {
				t.Fatal(err)
			}
			if id, exists := mapping[42]; !exists || id != 0 {
				t.Errorf("rejected asset lacks explicit skipped mapping: %v", mapping)
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], "跳过") {
				t.Errorf("expected one skip warning, got %v", warnings)
			}
		})
	}
}

func TestSecurityArchiveRemapDropsSkippedAssetReferences(t *testing.T) {
	tables := map[string]json.RawMessage{
		"exploration_anchors": json.RawMessage(`[{"node_id":1,"asset_id":10},{"node_id":1,"asset_id":20},{"node_id":1,"asset_id":30}]`),
		"task_asset_links":    json.RawMessage(`[{"task_id":1,"asset_id":10},{"task_id":1,"asset_id":20},{"task_id":1,"asset_id":30}]`),
		"findings":            json.RawMessage(`[{"summary":"keep finding","asset_ids":[10,20,30,10]},{"asset_ids":[10]}]`),
		"exploration_nodes":   json.RawMessage(`[{"payload":{"summary":"keep node","asset_ids":[10,20,30,10]}},{"payload":{"asset_ids":[10]}}]`),
	}
	original, _ := json.Marshal(tables)
	// Zero is an explicit skip; absent entries keep their preexisting semantics.
	got, err := remapArchiveAssetReferences(tables, map[int64]int64{10: 0, 20: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exploration_anchors", "task_asset_links"} {
		rows, err := decodeArchiveRows(got[name])
		if err != nil {
			t.Fatal(err)
		}
		ids := []int64{}
		for _, row := range rows {
			id, _ := jsonInt64(row["asset_id"])
			ids = append(ids, id)
		}
		if !reflect.DeepEqual(ids, []int64{200, 30}) {
			t.Errorf("%s references = %v, want [200 30]", name, ids)
		}
	}
	for _, name := range []string{"findings", "exploration_nodes"} {
		rows, err := decodeArchiveRows(got[name])
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("%s: dropping an asset must preserve both evidence rows", name)
		}
		for i, row := range rows {
			if name == "exploration_nodes" {
				row = row["payload"].(map[string]any)
			}
			ids, ok := row["asset_ids"].([]any)
			if !ok {
				t.Fatalf("%s[%d].asset_ids must remain an array: %#v", name, i, row["asset_ids"])
			}
			want := []int64{}
			if i == 0 {
				want = []int64{200, 30}
			}
			actual := []int64{}
			for _, value := range ids {
				id, _ := jsonInt64(value)
				actual = append(actual, id)
			}
			if !reflect.DeepEqual(actual, want) {
				t.Errorf("%s[%d] references = %v, want %v", name, i, actual, want)
			}
		}
	}
	after, _ := json.Marshal(tables)
	if string(original) != string(after) {
		t.Fatal("remapping mutated the original archive snapshot")
	}
}

// Exercise the complete PostgreSQL restore transaction, including FK insertion
// and a natural-key remap of a valid asset alongside the rejected legacy URL.
func TestSecurityPGArchiveRestoreDropsSkippedAssetReferences(t *testing.T) {
	for _, mode := range []string{"missing_id", "occupied_id", "existing_unsafe_url"} {
		t.Run(mode, func(t *testing.T) {
			d := openDisposableSchemaDB(t)
			if err := d.EnsureLLMRecordsTable(); err != nil {
				t.Fatal(err)
			}
			if err := d.EnsureLLMUsageTable(); err != nil {
				t.Fatal(err)
			}
			task, err := d.CreateTaskWithOptions("restore URL references", "preserve safe evidence", TaskCreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := d.SetPaused(task.ID, true); err != nil {
				t.Fatal(err)
			}
			const safeURL = "https://archive-safe.example.test/"
			const unsafeURL = "javascript:alert(1)"
			// Insert only the two services owned by this fixture. Upserting with
			// TaskID would also associate derived host assets, obscuring the exact
			// link set this restore test must verify.
			var safeID int64
			if err := d.QueryRow(`INSERT INTO assets(type,service_type,url,task_ids)
VALUES('service','http',$1,ARRAY[$2::bigint]) RETURNING id`, safeURL, task.ID).Scan(&safeID); err != nil {
				t.Fatal(err)
			}
			var unsafeID int64
			// Model a legacy row that predates URL validation; no payload executes.
			if err := d.QueryRow(`INSERT INTO assets(type,service_type,url,task_ids)
VALUES('service','http',$1,ARRAY[$2::bigint]) RETURNING id`, unsafeURL, task.ID).Scan(&unsafeID); err != nil {
				t.Fatal(err)
			}
			store := d.Exploration(task.ExplorationID)
			nodeID, err := store.AddNode(KindFact, map[string]any{"summary": "preserved evidence", "asset_ids": []int64{unsafeID, safeID}}, 1, "confirmed", "worker", nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []int64{unsafeID, safeID} {
				if err := store.Anchor(nodeID, id); err != nil {
					t.Fatal(err)
				}
			}
			findingID, err := d.AddFinding(task.ID, nodeID, "archive fixture", "preserved finding", SeverityHigh, "preserved summary", "evidence", "worker", []int64{unsafeID, safeID})
			if err != nil {
				t.Fatal(err)
			}
			archive, err := d.QueueTaskArchive(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			if claimed, err := d.ClaimTaskArchiveJob(t.Context()); err != nil || claimed == nil || claimed.State != Archiving {
				t.Fatalf("archive claim = %+v, %v", claimed, err)
			}
			snapshot, err := d.SnapshotTaskArchive(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/security-fixture.tar.zst", "fixture", 1, 1); err != nil {
				t.Fatal(err)
			}
			if mode == "occupied_id" {
				if _, err := d.Exec(`INSERT INTO assets(id,type,domain) VALUES($1,'root_domain','unrelated.example.test')`, unsafeID); err != nil {
					t.Fatal(err)
				}
			} else if mode == "existing_unsafe_url" {
				if _, err := d.Exec(`INSERT INTO assets(type,service_type,url) VALUES('service','http',$1)`, unsafeURL); err != nil {
					t.Fatal(err)
				}
			}
			newSafeID, err := d.Assets().UpsertHTTPService(UpsertHTTPServiceReq{URL: safeURL})
			if err != nil || newSafeID == safeID {
				t.Fatalf("safe natural-key remap fixture: old=%d new=%d err=%v", safeID, newSafeID, err)
			}
			if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
				t.Fatal(err)
			}
			if claimed, err := d.ClaimTaskArchiveJob(t.Context()); err != nil || claimed == nil || claimed.State != Restoring {
				t.Fatalf("restore claim = %+v, %v", claimed, err)
			}
			warnings, err := d.RestoreTaskArchive(archive.ID, snapshot, 0)
			if err != nil {
				t.Fatalf("restore must not fail on a rejected asset reference: %v", err)
			}
			if !strings.Contains(strings.Join(warnings, "\n"), "跳过") {
				t.Errorf("missing rejected URL warning: %v", warnings)
			}
			for _, query := range []string{
				`SELECT COALESCE(json_agg(asset_id ORDER BY asset_id),'[]')::text FROM exploration_anchors WHERE node_id=$1`,
				`SELECT COALESCE(json_agg(asset_id ORDER BY asset_id),'[]')::text FROM task_asset_links WHERE task_id=$1`,
				`SELECT asset_ids::text FROM findings WHERE id=$1`,
				`SELECT (payload->'asset_ids')::text FROM exploration_nodes WHERE id=$1`,
			} {
				id := nodeID
				if strings.Contains(query, "task_asset_links") {
					id = task.ID
				} else if strings.Contains(query, "FROM findings") {
					id = findingID
				}
				var raw string
				if err := d.QueryRow(query, id).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var ids []int64
				if err := json.Unmarshal([]byte(raw), &ids); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(ids, []int64{newSafeID}) {
					t.Errorf("restored references %v, want [%d] for %s", ids, newSafeID, query)
				}
			}
			var count int
			if err := d.QueryRow(`SELECT count(*) FROM assets WHERE $1=ANY(task_ids) AND id<>$2`, task.ID, newSafeID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Error("restore associated a rejected or unrelated asset with the task")
			}
			if mode == "occupied_id" {
				var domain string
				if err := d.QueryRow(`SELECT domain FROM assets WHERE id=$1`, unsafeID).Scan(&domain); err != nil || domain != "unrelated.example.test" {
					t.Fatalf("unrelated asset was changed: %q, %v", domain, err)
				}
			}
			var summary string
			if err := d.QueryRow(`SELECT summary FROM findings WHERE id=$1`, findingID).Scan(&summary); err != nil || summary != "preserved summary" {
				t.Fatalf("finding evidence lost: %q, %v", summary, err)
			}
		})
	}
}
