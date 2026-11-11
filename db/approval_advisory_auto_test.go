package db

import (
	"os"
	"testing"
	"time"
)

func autoTestDB(t *testing.T) *DB {
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
	return d
}

func TestApprovalAdvisoryAutoConfigConsent(t *testing.T) {
	d := autoTestDB(t)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM settings WHERE key LIKE 'approval_advisory_%'`)
	})
	if err := d.SaveAdvisoryAutoConfig(AdvisoryAutoConfig{Enabled: true, GlobalSlots: 4, MaxRetries: 2, DailyBudget: 10}); err == nil {
		t.Fatal("enabled without consent accepted")
	}
	consent := time.Now().UTC()
	if err := d.SaveAdvisoryAutoConfig(AdvisoryAutoConfig{Enabled: true, ConsentAt: consent, GlobalSlots: 4, MaxRetries: 2, DailyBudget: 10}); err != nil {
		t.Fatal(err)
	}
	cfg, err := d.ReadAdvisoryAutoConfig(t.Context())
	if err != nil || !cfg.Ready || !cfg.Enabled {
		t.Fatalf("config=%+v err=%v", cfg, err)
	}
}

func TestApprovalAdvisoryAutoBudgetAndCancel(t *testing.T) {
	d, id, _ := advisoryDBFixture(t)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM settings WHERE key LIKE 'approval_advisory_%'`)
	})
	ok, err := d.ConsumeAdvisoryDailyBudget(t.Context(), 2)
	if err != nil || !ok {
		t.Fatal("first consume", ok, err)
	}
	ok, err = d.ConsumeAdvisoryDailyBudget(t.Context(), 2)
	if err != nil || !ok {
		t.Fatal("second consume", ok, err)
	}
	ok, err = d.ConsumeAdvisoryDailyBudget(t.Context(), 2)
	if err != nil || ok {
		t.Fatal("budget should exhaust", ok, err)
	}
	if err := d.CancelApprovalAdvisoryAuto(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	meta, err := d.ReadAdvisoryAutoMeta(t.Context(), id)
	if err != nil || meta == nil || !meta.Cancelled {
		t.Fatalf("meta=%+v err=%v", meta, err)
	}
}

func TestApprovalAdvisoryGlobalSlot(t *testing.T) {
	d := autoTestDB(t)
	release, ok, err := d.TryAdvisoryGlobalSlot(t.Context(), 2)
	if err != nil || !ok {
		t.Fatal(err, ok)
	}
	defer release()
	_, ok2, err := d.TryAdvisoryGlobalSlot(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !ok2 {
		t.Fatal("second slot expected")
	}
	_, ok3, err := d.TryAdvisoryGlobalSlot(t.Context(), 2)
	if err != nil || ok3 {
		t.Fatal("third slot should fail", ok3, err)
	}
}

func TestApprovalAdvisoryAutoRetryMeta(t *testing.T) {
	d, id, _ := advisoryDBFixture(t)
	if err := d.RecordAdvisoryAutoFailure(t.Context(), id, "timeout", 2); err != nil {
		t.Fatal(err)
	}
	meta, err := d.ReadAdvisoryAutoMeta(t.Context(), id)
	if err != nil || meta == nil || meta.Attempts != 1 || meta.NextRetryAt == nil {
		t.Fatalf("meta=%+v err=%v", meta, err)
	}
	if err := d.RecordAdvisoryAutoFailure(t.Context(), id, "timeout", 2); err != nil {
		t.Fatal(err)
	}
	meta, err = d.ReadAdvisoryAutoMeta(t.Context(), id)
	if err != nil || meta.Attempts != 2 {
		t.Fatalf("meta=%+v", meta)
	}
	if err := d.RecordAdvisoryAutoFailure(t.Context(), id, "timeout", 2); err != nil {
		t.Fatal(err)
	}
	meta, err = d.ReadAdvisoryAutoMeta(t.Context(), id)
	if err != nil || meta.NextRetryAt != nil {
		t.Fatal("retries exhausted should clear next_retry_at")
	}
}

func TestApprovalAdvisoryListPendingFIFO(t *testing.T) {
	d := autoTestDB(t)
	a, err := d.CreateInterceptPending(0, 0, "", "f", "Write", []byte(`{"a":1}`), "one")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	b, err := d.CreateInterceptPending(0, 0, "", "f", "Write", []byte(`{"b":2}`), "two")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE id IN ($1,$2)`, a, b)
	})
	ids, err := d.ListPendingIDsForAutoAdvisory(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) < 2 || ids[0] != a {
		t.Fatalf("fifo order: got %v want head %d", ids, a)
	}
}

func TestApprovalAdvisoryAutoConfigDisabled(t *testing.T) {
	d := autoTestDB(t)
	if err := d.SaveAdvisoryAutoConfig(AdvisoryAutoConfig{Enabled: false, GlobalSlots: 8, MaxRetries: 3, DailyBudget: 100}); err != nil {
		t.Fatal(err)
	}
	cfg, err := d.ReadAdvisoryAutoConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("should remain disabled")
	}
	if cfg.Ready {
		t.Fatal("ready without consent")
	}
	ok, err := d.ConsumeAdvisoryDailyBudget(t.Context(), 0)
	if err != nil || ok {
		t.Fatal("zero budget must not consume", ok, err)
	}
}
