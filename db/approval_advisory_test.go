package db

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/approvalreview"
)

func advisoryDBFixture(t *testing.T) (*DB, int64, ApprovalAdvisory) {
	t.Helper()
	dsn := os.Getenv("ARTEX_AUTH_TEST_DSN")
	if dsn == "" {
		t.Skip("ARTEX_AUTH_TEST_DSN unset: disposable PostgreSQL required")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	id, err := d.CreateInterceptPending(0, 0, "", "fixture", "Write", []byte(`{"path":"fixture.txt"}`), "manual review")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM intercept_pending WHERE id=$1`, id) })
	src, err := d.ReadApprovalAdvisory(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return d, id, ApprovalAdvisory{Fingerprint: strings.Repeat("a", 64), ActionFingerprint: src.Fingerprint(), ProfileID: 42, Model: "fixture"}
}

func advisoryResult() *approvalreview.Result {
	return &approvalreview.Result{Risk: "low", Summary: "synthetic fixture", Consequences: "local fixture only", Recommendation: "consider_approval", Suggestions: []string{"review manually"}}
}

func TestApprovalAdvisoryPGSingleFlightAndCache(t *testing.T) {
	d, id, attempt := advisoryDBFixture(t)
	var count atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, won, err := d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second)
			if err != nil {
				t.Error(err)
			}
			if won {
				count.Add(1)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("claimed %d times", count.Load())
	}
	src, err := d.ReadApprovalAdvisory(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if src.Status != "pending" {
		t.Fatal("advisory changed approval")
	}
	if ok, err := d.FinishApprovalAdvisory(t.Context(), id, src.Advisory.LeaseID, advisoryResult(), "", false); err != nil || !ok {
		t.Fatalf("finish %v %v", ok, err)
	}
	cached, won, err := d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second)
	if err != nil || won || cached.State != "succeeded" {
		t.Fatalf("cache %+v %v %v", cached, won, err)
	}
	// Reopening the DB represents a new process; successful answers remain saved.
	other, err := Open(os.Getenv("ARTEX_AUTH_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	cached, won, err = other.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second)
	if err != nil || won || cached.Result == nil {
		t.Fatal("saved assessment not reused")
	}
	detail, err := d.GetInterceptDetail(id)
	if err != nil || detail.Audit != nil {
		t.Fatalf("legacy audit fabricated: %+v %v", detail, err)
	}
}

func TestApprovalAdvisoryPGDecisionWins(t *testing.T) {
	d, id, attempt := advisoryDBFixture(t)
	claimed, _, err := d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.ResolveIntercept(id, "denied", "deny", "human decision"); err != nil || !ok {
		t.Fatal(err)
	}
	if ok, err := d.FinishApprovalAdvisory(t.Context(), id, claimed.LeaseID, advisoryResult(), "", false); err != nil || !ok {
		t.Fatal(err)
	}
	src, err := d.ReadApprovalAdvisory(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if src.Status != "denied" || src.Advisory.State != "stale" || src.Advisory.Result != nil {
		t.Fatalf("late advice: %+v", src)
	}
	detail, err := d.GetInterceptDetail(id)
	if err != nil || detail.Audit != nil {
		t.Fatal("settlement manufactured a legacy execution snapshot", err)
	}
	if _, _, err := d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second); !errors.Is(err, ErrAdvisoryNotPending) {
		t.Fatalf("settled approval accepted: %v", err)
	}
}

func TestApprovalAdvisoryPGLeaseOwnership(t *testing.T) {
	d, id, attempt := advisoryDBFixture(t)
	first, _, err := d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Write an RFC3339 timestamp instead of relying on PostgreSQL text format.
	expired, _ := json.Marshal(time.Now().Add(-time.Minute).UTC())
	_, err = d.Exec(`UPDATE intercept_pending SET audit=jsonb_set(audit,'{approval_advisory,lease_until}',$2::jsonb) WHERE id=$1`, id, expired)
	if err != nil {
		t.Fatal(err)
	}
	second, won, err := d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second)
	if err != nil || !won || first.LeaseID == second.LeaseID {
		t.Fatal("expired lease not replaced", err)
	}
	if ok, err := d.FinishApprovalAdvisory(t.Context(), id, first.LeaseID, advisoryResult(), "", false); err != nil || ok {
		t.Fatal("old owner published", err)
	}
	if ok, err := d.FinishApprovalAdvisory(t.Context(), id, second.LeaseID, nil, "timeout", false); err != nil || !ok {
		t.Fatal(err)
	}
	src, err := d.ReadApprovalAdvisory(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if src.Status != "pending" || src.Advisory.State != "failed" || src.Advisory.Result != nil {
		t.Fatalf("failure changed decision: %+v", src)
	}
	_, won, err = d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second)
	if err != nil || !won {
		t.Fatal("explicit retry refused", err)
	}
}

func TestApprovalAdvisoryPGSnapshotAndAuditPreservation(t *testing.T) {
	d, id, attempt := advisoryDBFixture(t)
	_, err := d.Exec(`UPDATE intercept_pending SET audit='{"run_id":"original","context":[{"text":"keep"}]}' WHERE id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`UPDATE intercept_pending SET tool_input='{"path":"different.txt"}' WHERE id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.FinishApprovalAdvisory(t.Context(), id, first.LeaseID, advisoryResult(), "", false); err != nil || !ok {
		t.Fatal(err)
	}
	src, err := d.ReadApprovalAdvisory(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if src.Advisory.State != "stale" || src.Status != "pending" {
		t.Fatalf("action edit accepted: %+v", src)
	}
	if _, _, err := d.ClaimApprovalAdvisory(t.Context(), id, attempt, time.Second); !errors.Is(err, ErrAdvisoryChanged) {
		t.Fatal("old input admitted", err)
	}
	var run, contextText string
	if err := d.QueryRow(`SELECT audit->>'run_id',audit->'context'->0->>'text' FROM intercept_pending WHERE id=$1`, id).Scan(&run, &contextText); err != nil {
		t.Fatal(err)
	}
	if run != "original" || contextText != "keep" {
		t.Fatal("original audit overwritten")
	}
}

func TestApprovalAdvisoryPGInputBound(t *testing.T) {
	d, id, _ := advisoryDBFixture(t)
	raw, _ := json.Marshal(map[string]string{"command": strings.Repeat("x", approvalreview.MaxInputBytes)})
	if _, err := d.Exec(`UPDATE intercept_pending SET tool_input=$2 WHERE id=$1`, id, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadApprovalAdvisory(t.Context(), id); !errors.Is(err, ErrAdvisoryTooLarge) {
		t.Fatal("oversized action accepted", err)
	}
}
