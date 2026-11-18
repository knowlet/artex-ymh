package db

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestReviewRetryLockCancellationAndFreshClaim(t *testing.T) {
	d, s, id := modelRetryTestStore(t)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT id FROM exploration_nodes WHERE id=$1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := s.ScheduleIntentModelRetryContext(ctx, id, 2, 0, time.Time{}, "fixture-revision")
		done <- e
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled scheduling succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not release lock wait")
	}
	tx.Rollback()
	r, err := s.ScheduleIntentModelRetryContext(t.Context(), id, 2, time.Millisecond, time.Time{}, "fixture-revision")
	if err != nil || !r.Scheduled {
		t.Fatalf("schedule=%+v %v", r, err)
	}
	if _, err := d.Exec(`UPDATE exploration_nodes SET model_retry_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	node, err := s.ClaimIntentNode(id, "fresh")
	if err != nil || node == nil || node.ModelRetryCount != 1 || node.ModelRetryRevision != "fixture-revision" || node.State != "running" {
		t.Fatalf("claim=%+v %v", node, err)
	}
}
func TestReviewArchiveSnapshotCancellation(t *testing.T) {
	d, _, _ := modelRetryTestStore(t)
	task, err := d.CreateTask(t.Name(), "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := d.SnapshotTaskArchiveWithLLMRecordsContext(ctx, task.ID, io.Discard); done <- e }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled snapshot succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("archive lock ignored cancellation")
	}
}
func TestReviewQuotaTransitionLockCancellation(t *testing.T) {
	d, _, _ := modelRetryTestStore(t)
	task, err := d.CreateTask(t.Name(), "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, task.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := d.MarkTaskLLMProfileQuotaExhaustedContext(ctx, task.ID, 1, 0, "fixture quota")
		done <- e
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled quota mutation succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("quota mutation ignored call deadline")
	}
}
