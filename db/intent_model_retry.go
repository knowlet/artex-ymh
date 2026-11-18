package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// IntentModelRetry is the committed recovery decision for one failed worker.
// A deferred intent stays open, so planner/task-completion checks still see work.
type IntentModelRetry struct {
	Scheduled bool
	Attempt   int
	RetryAt   time.Time
	Stop      string // disabled, exhausted, deadline, or state_changed
}

// ModelRetryDelay deliberately leaves enough time for a provider to recover.
// The configured positive interval keeps its fixed-delay semantics.
func ModelRetryDelay(attempt int, interval time.Duration) time.Duration {
	if interval > 0 {
		return min(interval, time.Hour)
	}
	switch {
	case attempt <= 1:
		return time.Minute
	case attempt == 2:
		return 5 * time.Minute
	default:
		return 30 * time.Minute
	}
}

// ScheduleIntentModelRetry atomically parks a still-running intent until its next
// attempt. Only the engine calls this after classifying a transient model error
// and checking that the worker has a resumable transcript. The count survives
// process restarts, claims, and pause/resume; explicit manual reruns reset it.
// It never changes a terminal/paused/deleted intent or reopens old blocked work.
func (s *ExplorationStore) ScheduleIntentModelRetry(id int64, maxRetries int, interval time.Duration, deadline time.Time) (IntentModelRetry, error) {
	return s.ScheduleIntentModelRetryContext(context.Background(), id, maxRetries, interval, deadline, "")
}
func (s *ExplorationStore) ScheduleIntentModelRetryContext(ctx context.Context, id int64, maxRetries int, interval time.Duration, deadline time.Time, revision string) (IntentModelRetry, error) {
	var out IntentModelRetry
	if maxRetries <= 0 {
		out.Stop = "disabled"
		return out, nil
	}
	maxRetries = min(maxRetries, maxRetryAttempts)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var state string
	var now time.Time
	err = tx.QueryRowContext(ctx, `SELECT state, model_retry_count FROM exploration_nodes
WHERE id=$1 AND exploration_id=$2 AND kind='intent' FOR UPDATE`, id, s.expID).
		Scan(&state, &out.Attempt)
	if err == sql.ErrNoRows {
		return out, fmt.Errorf("intent not found")
	}
	if err != nil {
		return out, err
	}
	if state != "running" {
		out.Stop = "state_changed"
		return out, nil
	}
	if out.Attempt >= maxRetries {
		out.Stop = "exhausted"
		return out, nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	out.Attempt++
	out.RetryAt = now.Add(ModelRetryDelay(out.Attempt, interval))
	if !deadline.IsZero() && !out.RetryAt.Before(deadline) {
		out.Stop = "deadline"
		return out, nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE exploration_nodes
SET state='open', owner=NULL, blocked_reason=NULL, completed_at=NULL,
    model_retry_count=$3, model_retry_at=$4, model_retry_revision=$5, content_version=content_version+1
WHERE id=$1 AND exploration_id=$2`, id, s.expID, out.Attempt, out.RetryAt, revision)
	if err != nil {
		return out, err
	}
	if err := tx.Commit(); err != nil {
		return out, err
	}
	out.Scheduled = true
	return out, nil
}

// A revision guards admission to one scheduled recovery attempt. Once the
// verified history has been loaded, ordinary pause/resume may advance it without
// resetting the durable retry count. A later scheduled retry records a new hash.
const ConsumedModelRetryRevisionPrefix = "validated:"

func (s *ExplorationStore) ConsumeIntentModelRetryRevision(ctx context.Context, id int64, revision string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE exploration_nodes SET model_retry_revision=$3
WHERE id=$1 AND exploration_id=$2 AND kind='intent' AND state='running' AND model_retry_revision=$4`, id, s.expID, ConsumedModelRetryRevisionPrefix+revision, revision)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
