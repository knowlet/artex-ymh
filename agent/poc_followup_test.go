package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func pocFollowupPGStore(t *testing.T) *db.ExplorationStore {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no disposable PostgreSQL configured: %v", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	id, err := d.CreateExploration(t.Name(), "poc follow-up fixture")
	if err != nil {
		t.Fatalf("CreateExploration: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, id) })
	return d.Exploration(id)
}

func TestAccessVulnCandidateFactClassification(t *testing.T) {
	cases := []struct {
		sum, det, conf string
		want           bool
		kind           string
	}{
		{"成功获取合法 session cookie", "", "observed", true, "session_access"},
		{"Got interactive shell as www-data", "whoami output", "observed", true, "shell_rce"},
		{"端口无响应", "", "observed", false, ""},
		{"login page returns 200", "", "observed", false, ""},
		{"疑似 session 有效", "", "inferred", false, ""},
		{"命令执行成功", "id=0(root)", "inferred", true, "shell_rce"},
	}
	for _, c := range cases {
		ok, kind := accessVulnCandidateFact(c.sum, c.det, c.conf)
		if ok != c.want || kind != c.kind {
			t.Errorf("accessVulnCandidateFact(%q)=%v,%q want %v,%q", c.sum, ok, kind, c.want, c.kind)
		}
	}
}

func TestIntentLooksLikePOCVerification(t *testing.T) {
	if !intentLooksLikePOCVerification("验证 SQLi 并获取可复现 PoC", nil) {
		t.Fatal("expected poc verification intent")
	}
	if intentLooksLikePOCVerification("枚举子域", nil) {
		t.Fatal("enum intent must not match")
	}
	exp := map[string]any{"expected_signal": "可复现的漏洞响应"}
	if !intentLooksLikePOCVerification("跟进 session", exp) {
		t.Fatal("expected_signal should classify")
	}
}

func TestRenderPOCFollowupGuidanceOnlyOpenItems(t *testing.T) {
	data := map[string]any{
		"poc_verification_candidates": []map[string]any{
			{"fact_id": 1, "needs_followup": true, "summary": "session ok"},
			{"fact_id": 2, "needs_followup": false, "summary": "covered"},
		},
	}
	g := renderPOCFollowupGuidance(data)
	if !strings.Contains(g, "fact_id") || !strings.Contains(g, "session ok") {
		t.Fatalf("guidance missing actionable candidate: %q", g)
	}
	if strings.Contains(g, `"fact_id":2`) {
		t.Fatalf("covered candidate must not appear in guidance: %q", g)
	}
	if renderPOCFollowupGuidance(map[string]any{}) != "" {
		t.Fatal("empty overview should not render guidance")
	}
}

func TestBuildPOCFollowupSnapshotCompletedVerificationFinding(t *testing.T) {
	fact := &db.Node{ID: 10, Kind: db.KindFact, Payload: []byte(`{"summary":"登录成功并取得 session cookie","confidence":"observed"}`)}
	enum := &db.Node{ID: 5, Kind: db.KindIntent, State: "done", Payload: []byte(`{"summary":"枚举登录"}`)}
	verify := &db.Node{ID: 30, Kind: db.KindIntent, State: "done", Payload: []byte(`{"summary":"验证 session 越权 PoC"}`)}
	finding := &db.Node{ID: 40, Kind: db.KindFinding, Payload: []byte(`{"summary":"session hijack confirmed"}`)}
	parentsOf := map[int64][]int64{30: {10}}
	yieldsOf := map[int64][]int64{5: {10}, 30: {40}}
	factFrom := map[int64]int64{10: 5}
	all := []*db.Node{enum, verify}
	snap := buildPOCFollowupSnapshot([]*db.Node{fact}, []*db.Node{finding}, all, parentsOf, yieldsOf, factFrom, nil)
	if len(snap.Candidates) != 0 {
		t.Fatalf("finding via verification child must not re-open candidate: %+v", snap.Candidates)
	}
}

func TestBuildPOCFollowupSnapshotCompletedVerificationNoFinding(t *testing.T) {
	fact := &db.Node{ID: 10, Kind: db.KindFact, Payload: []byte(`{"summary":"authenticated session established","confidence":"observed"}`)}
	verify := &db.Node{ID: 30, Kind: db.KindIntent, State: "done", Payload: []byte(`{"summary":"verify session PoC"}`)}
	parentsOf := map[int64][]int64{30: {10}}
	yieldsOf := map[int64][]int64{30: {99}}
	factFrom := map[int64]int64{10: 5}
	snap := buildPOCFollowupSnapshot([]*db.Node{fact}, nil, []*db.Node{verify}, parentsOf, yieldsOf, factFrom, nil)
	if len(snap.Candidates) != 1 {
		t.Fatalf("negative closure should remain visible: %+v", snap.Candidates)
	}
	if snap.Candidates[0]["needs_followup"] != false {
		t.Fatalf("completed verification without finding is terminal closure: %+v", snap.Candidates[0])
	}
	if g := renderPOCFollowupGuidance(map[string]any{"poc_verification_candidates": snap.Candidates}); g != "" {
		t.Fatalf("terminal negative verification must not nag planner: %q", g)
	}
}

func TestBuildPOCFollowupSnapshotUnit(t *testing.T) {
	fact := &db.Node{ID: 10, Kind: db.KindFact, Payload: []byte(`{"summary":"登录成功并取得 session cookie","confidence":"observed"}`)}
	open := []*db.Node{{ID: 20, Kind: db.KindIntent, State: "open", Payload: []byte(`{"summary":"verify poc"}`)}}
	parentsOf := map[int64][]int64{20: {10}}
	factFrom := map[int64]int64{10: 5}
	snap := buildPOCFollowupSnapshot([]*db.Node{fact}, nil, open, parentsOf, map[int64][]int64{}, factFrom, open)
	if len(snap.Candidates) != 1 {
		t.Fatalf("expected candidate, got %+v", snap.Candidates)
	}
	if snap.Candidates[0]["needs_followup"] != false {
		t.Fatalf("parent-linked open intent should cover: %+v", snap.Candidates[0])
	}
}

func TestGraphOverviewPOCFollowupIntegration(t *testing.T) {
	t.Setenv("ARTEX_PLANNER_POC_FOLLOWUP", "1")
	store := pocFollowupPGStore(t)
	enumID, err := store.AddIntent(map[string]any{"summary": "枚举登录面"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	factID, err := store.AddNode("fact", map[string]any{
		"summary": "登录成功并取得合法 session cookie", "confidence": "observed",
	}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Link(enumID, db.RelYields, factID); err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(store, "planner")
	overview := ts.graphOverviewData()
	cands, ok := overview["poc_verification_candidates"].([]map[string]any)
	if !ok || len(cands) != 1 {
		t.Fatalf("expected one candidate, got %#v", overview["poc_verification_candidates"])
	}
	if needs, _ := cands[0]["needs_followup"].(bool); !needs {
		t.Fatalf("candidate should need followup: %#v", cands[0])
	}
	guidance := renderPOCFollowupGuidance(overview)
	if guidance == "" || !strings.Contains(guidance, fmt.Sprint(factID)) {
		t.Fatalf("planner guidance must mention fact %d: %q", factID, guidance)
	}

	verifyID, err := store.AddIntent(map[string]any{
		"summary": "验证 session 越权读取并获取可复现 PoC",
	}, 6, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Link(factID, db.RelDerivedFrom, verifyID); err != nil {
		t.Fatal(err)
	}
	_ = verifyID
	overview2 := ts.graphOverviewData()
	cands2, _ := overview2["poc_verification_candidates"].([]map[string]any)
	if len(cands2) != 1 {
		t.Fatalf("still one candidate entry: %#v", cands2)
	}
	if needs, _ := cands2[0]["needs_followup"].(bool); needs {
		t.Fatalf("open child should cover followup: %#v", cands2[0])
	}
	if renderPOCFollowupGuidance(overview2) != "" {
		t.Fatalf("covered chain should not nag planner")
	}

	if err := store.SetIntentState(verifyID, "done"); err != nil {
		t.Fatal(err)
	}
	findingID, err := store.AddNode(db.KindFinding, map[string]any{"summary": "session hijack with reproducible PoC"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Link(verifyID, db.RelYields, findingID); err != nil {
		t.Fatal(err)
	}
	overview3 := ts.graphOverviewData()
	if cands3, _ := overview3["poc_verification_candidates"].([]map[string]any); len(cands3) != 0 {
		t.Fatalf("completed verification finding must drop candidate: %#v", cands3)
	}
	if renderPOCFollowupGuidance(overview3) != "" {
		t.Fatalf("successful PoC must not request another verification")
	}
}

func TestGraphOverviewBlockedPOCRetryHints(t *testing.T) {
	t.Setenv("ARTEX_PLANNER_POC_FOLLOWUP", "1")
	store := pocFollowupPGStore(t)
	parent, err := store.AddIntent(map[string]any{"summary": "发现登录入口"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	factID, err := store.AddNode("fact", map[string]any{
		"summary": "authenticated session established", "confidence": "observed",
	}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Link(parent, db.RelYields, factID); err != nil {
		t.Fatal(err)
	}
	verifyID, err := store.AddIntent(map[string]any{
		"summary": "验证 session 劫持并收集 PoC",
	}, 6, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Link(factID, db.RelDerivedFrom, verifyID); err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(verifyID, "w1"); err != nil || !claimed {
		t.Fatal(err)
	}
	if err := store.SetNodeState(verifyID, "blocked"); err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(store, "planner")
	overview := ts.graphOverviewData()
	retries, ok := overview["blocked_poc_retries"].([]map[string]any)
	if !ok || len(retries) != 1 {
		t.Fatalf("blocked retry hint missing: %#v", overview["blocked_poc_retries"])
	}
	if id, _ := retries[0]["intent_id"].(int64); id != verifyID {
		t.Fatalf("wrong intent in retry hint: %#v", retries[0])
	}
	b, _ := json.Marshal(overview["blocked_poc_retries"])
	if retries[0]["needs_followup"] != false || retries[0]["manual_review_required"] != true || renderPOCFollowupGuidance(overview) != "" {
		t.Fatalf("blocked work must not request automatic replacement: %s", b)
	}
	if strings.Contains(string(b), "planner_action") {
		t.Fatalf("covered blocked work must not request planner action: %s", b)
	}
}
