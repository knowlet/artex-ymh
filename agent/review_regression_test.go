package agent

import (
	"encoding/json"
	"errors"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
	"strconv"
	"strings"
	"testing"
)

func TestReviewGatewayTimeoutDiagnostic(t *testing.T) {
	if !IsTransientModelError(errors.New("HTTP 504 upstream took too long to respond")) {
		t.Fatal("gateway diagnostic hides retryable HTTP status")
	}
	if !IsTransientModelError(&CallTimeoutError{Model: "context_length_test"}) {
		t.Fatal("model alias changes typed timeout classification")
	}
}
func TestReviewToolStreamContextOverflow(t *testing.T) {
	p, _, ctx := toolWireFixture(t, `data: {"error":{"type":"ContextWindowExceededError","message":"fixture-private"}}`+"\n\n", true)
	var got error
	for _, err := range p.Stream(ctx, toolWireRequest()) {
		if err != nil {
			got = err
		}
	}
	if got == nil || !compaction.IsOverflow(got) || IsTransientModelError(got) || strings.Contains(got.Error(), "fixture-private") {
		t.Fatalf("overflow signal lost: %v", got)
	}
}
func TestReviewInferredGapDoesNotDispatch(t *testing.T) {
	if ok, _ := accessVulnCandidateFact("RCE was not reproduced", "", "inferred"); ok {
		t.Fatal("inferred evidence gap became actionable")
	}
	if ok, _ := accessVulnCandidateFact("possible RCE", "", "inferred"); ok {
		t.Fatal("keyword-only inference became actionable")
	}
}
func TestReviewOrphanResultCannotProveRecovery(t *testing.T) {
	if err := validateWorkerRetryTranscript([]llm.Message{llm.UserText("fixture"), {Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("a", "effect", false)}}}, []string{"a"}); err == nil {
		t.Fatal("orphan result credited")
	}
}
func TestReviewIntentAssetSetAndTerminalOutcome(t *testing.T) {
	d, s, _ := plannerProgressStore(t, 0)
	a, err := d.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: "first-review.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: "second-review.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(s, "planner")
	item := intentItem{Summary: "fixture work", AssetIDs: []json.RawMessage{json.RawMessage(strconv.FormatInt(a, 10)), json.RawMessage(strconv.FormatInt(b, 10))}}
	id, err := tools.addOneIntent(item)
	if err != nil {
		t.Fatal(err)
	}
	item.AssetIDs = []json.RawMessage{json.RawMessage(strconv.FormatInt(b, 10)), json.RawMessage(strconv.FormatInt(a, 10)), json.RawMessage(strconv.FormatInt(a, 10))}
	got, err := tools.addOneIntent(item)
	if err != nil || got != id {
		t.Fatalf("asset set changed identity %d -> %d: %v", id, got, err)
	}
	// Historical payloads may predate canonical admission. Anchor identity remains a set.
	reversed, _ := json.Marshal([]int64{b, a, a})
	if _, err := d.Exec(`UPDATE exploration_nodes SET payload=jsonb_set(payload,'{asset_ids}',$2::jsonb) WHERE id=$1`, id, string(reversed)); err != nil {
		t.Fatal(err)
	}
	item.AssetIDs = []json.RawMessage{json.RawMessage(strconv.FormatInt(a, 10)), json.RawMessage(strconv.FormatInt(b, 10))}
	if got, err := tools.addOneIntent(item); err != nil || got != id {
		t.Fatalf("historical array bypassed identity %d -> %d %v", id, got, err)
	}
	if err := s.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	resumed := 0
	tools.SetResumeTask(func() { resumed++ })
	raw, _ := json.Marshal(map[string]any{"summary": "fixture work", "asset_ids": []int64{b, a}})
	res, err := tools.addIntent().Call(t.Context(), raw, nil)
	if err != nil || res.IsError || !strings.Contains(res.Flatten(), "reused") || !strings.Contains(res.Flatten(), "done") || resumed != 0 {
		t.Fatalf("terminal result=%s resume=%d err=%v", res.Flatten(), resumed, err)
	}
}
func TestReviewPOCPromptBounded(t *testing.T) {
	snap := pocFollowupSnapshot{}
	for i := range 1000 {
		snap.Candidates = append(snap.Candidates, map[string]any{"fact_id": i, "summary": strings.Repeat("文", 1000), "needs_followup": i >= 990})
	}
	out := map[string]any{}
	boundPOCFollowupSnapshot(&snap, out)
	b, _ := json.Marshal(snap.Candidates)
	if len(snap.Candidates) != 20 || out["poc_verification_candidate_count"] != 1000 || len(b) > 20000 {
		t.Fatalf("unbounded prompt count=%d bytes=%d totals=%v", len(snap.Candidates), len(b), out)
	}
	for i := range 10 {
		if snap.Candidates[i]["needs_followup"] != true {
			t.Fatal("covered history displaced actionable candidates")
		}
	}
}
func TestReviewFactDecodeFailureDoesNotWrite(t *testing.T) {
	_, s, _ := plannerProgressStore(t, 0)
	tools := NewToolSet(s, "fixture")
	res, err := tools.recordFact().Call(t.Context(), json.RawMessage(`{"facts":[{"summary":"first"},{"summary":"second","evidence":3}]}`), nil)
	nodes, readErr := s.ListByKind(db.KindFact, 100)
	if err != nil || !res.IsError || readErr != nil || len(nodes) != 0 {
		t.Fatalf("partial fact write accepted result=%s nodes=%d err=%v/%v", res.Flatten(), len(nodes), err, readErr)
	}
}

func TestReviewUnicodeArgumentAmbiguity(t *testing.T) {
	for _, raw := range []string{`{"summary":"first","ſummary":"second"}`, `{"intents":[{"summary":"fixture"}],"aſset_ids":[7]}`} {
		if _, _, err := parseIntentArguments([]byte(raw)); err == nil {
			t.Fatalf("ambiguous decoder keys accepted: %s", raw)
		}
	}
}
