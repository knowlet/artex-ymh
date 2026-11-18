package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/approvalreview"
)

// Advisory records are an isolated audit member. None of these methods change
// the approval status, deadline, decision source or the intercept wait channel.
var ErrAdvisoryNotPending = errors.New("approval is no longer pending")
var ErrAdvisoryChanged = errors.New("approval action changed")
var ErrAdvisoryTooLarge = errors.New("approval snapshot exceeds advisory limit")

// ApprovalAdvisory stores only the latest attempt. LeaseID is internal ownership,
// not an authorization token, and must be omitted by the API response view.
type ApprovalAdvisory struct {
	Version           string                 `json:"version"`
	State             string                 `json:"state"`
	Trigger           string                 `json:"trigger,omitempty"` // manual|auto
	Fingerprint       string                 `json:"fingerprint"`
	ActionFingerprint string                 `json:"action_fingerprint"`
	ProfileID         int64                  `json:"profile_id"`
	Model             string                 `json:"model"`
	ProfileVersion    string                 `json:"profile_version"`
	StartedAt         time.Time              `json:"started_at"`
	FinishedAt        *time.Time             `json:"finished_at,omitempty"`
	LeaseUntil        time.Time              `json:"lease_until"`
	LeaseID           string                 `json:"lease_id"`
	ErrorCode         string                 `json:"error_code,omitempty"`
	Result            *approvalreview.Result `json:"result,omitempty"`
}

// ApprovalAdvisorySource excludes conversation history, execution output and
// provider credentials. ModelInput is the recorded action-review snapshot, not replayed.
type ApprovalAdvisorySource struct {
	RuleID     *int64            `json:"rule_id"`
	ID         int64             `json:"id"`
	Tool       string            `json:"tool"`
	Input      json.RawMessage   `json:"input"`
	Reason     string            `json:"reason"`
	TaskID     string            `json:"task_id"`
	ModelInput json.RawMessage   `json:"model_input,omitempty"`
	Status     string            `json:"-"`
	Advisory   *ApprovalAdvisory `json:"-"`
}

func (s ApprovalAdvisorySource) Fingerprint() string {
	raw, _ := json.Marshal(s)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

type advisoryQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readApprovalAdvisory(ctx context.Context, q advisoryQuerier, id int64, lock bool) (*ApprovalAdvisorySource, error) {
	// Bound values before transferring them to the application. Refuse oversized
	// input rather than silently omit the portion that may contain the risk.
	query := `SELECT id, status, tool_name, COALESCE(task_id,''), rule_id,
		CASE WHEN octet_length(tool_input::text)<=$2 THEN tool_input END,
		CASE WHEN octet_length(reason)<=$2 THEN reason END,
		CASE WHEN octet_length(COALESCE(audit->'model_input','null'::jsonb)::text)<=$2
		THEN COALESCE(audit->'model_input','null'::jsonb) END,
		CASE WHEN octet_length(COALESCE(audit->'approval_advisory','null'::jsonb)::text)<=$2
		THEN COALESCE(audit->'approval_advisory','null'::jsonb) END
		FROM intercept_pending WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	var out ApprovalAdvisorySource
	var reason sql.NullString
	var raw, input, modelInput []byte
	err := q.QueryRowContext(ctx, query, id, approvalreview.MaxInputBytes).Scan(&out.ID, &out.Status, &out.Tool, &out.TaskID, &out.RuleID, &input, &reason, &modelInput, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if input == nil || !reason.Valid || modelInput == nil || raw == nil || len(out.Tool)+len(out.TaskID) > 4096 {
		return nil, ErrAdvisoryTooLarge
	}
	out.Input, out.ModelInput = json.RawMessage(input), json.RawMessage(modelInput)
	out.Reason = reason.String
	if err := json.Unmarshal(raw, &out.Advisory); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) ReadApprovalAdvisory(ctx context.Context, id int64) (*ApprovalAdvisorySource, error) {
	return readApprovalAdvisory(ctx, d, id, false)
}

// ClaimApprovalAdvisory serializes admission with human decisions and other
// reviewers. A successful matching review is reused; an unexpired running lease
// is joined even if settings changed. Inference never runs inside a DB lock.
func (d *DB) ClaimApprovalAdvisory(ctx context.Context, id int64, attempt ApprovalAdvisory, duration time.Duration) (*ApprovalAdvisory, bool, error) {
	if duration <= 0 || duration > 60*time.Second || len(attempt.Fingerprint) != 64 || len(attempt.ActionFingerprint) != 64 {
		return nil, false, errors.New("invalid advisory claim")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	src, err := readApprovalAdvisory(ctx, tx, id, true)
	if err != nil {
		return nil, false, err
	}
	if src == nil || src.Status != "pending" {
		return nil, false, ErrAdvisoryNotPending
	}
	if src.Fingerprint() != attempt.ActionFingerprint {
		return nil, false, ErrAdvisoryChanged
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return nil, false, err
	}
	if old := src.Advisory; old != nil && old.Version == approvalreview.Version {
		if old.State == "running" && now.Before(old.LeaseUntil) || old.State == "succeeded" && old.Fingerprint == attempt.Fingerprint && old.ActionFingerprint == attempt.ActionFingerprint && old.Result != nil {
			return old, false, nil
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, false, err
	}
	attempt.Version, attempt.State = approvalreview.Version, "running"
	if attempt.Trigger == "" {
		attempt.Trigger = "manual"
	}
	attempt.StartedAt, attempt.LeaseUntil = now.UTC(), now.Add(duration+30*time.Second).UTC()
	attempt.LeaseID = hex.EncodeToString(nonce[:])
	attempt.FinishedAt, attempt.Result, attempt.ErrorCode = nil, nil, ""
	if err := writeApprovalAdvisory(ctx, tx, id, attempt); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &attempt, true, nil
}

func writeApprovalAdvisory(ctx context.Context, tx *sql.Tx, id int64, a ApprovalAdvisory) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if len(raw) > approvalreview.MaxInputBytes {
		return ErrAdvisoryTooLarge
	}
	_, err = tx.ExecContext(ctx, `UPDATE intercept_pending SET audit=jsonb_set(
		COALESCE(NULLIF(audit,'null'::jsonb),'{"approval_advisory_only":true}'::jsonb),'{approval_advisory}',$2::jsonb,true) WHERE id=$1`, id, raw)
	return err
}

// FinishApprovalAdvisory uses the lease as a compare-and-swap. Expired owners and
// replaced attempts cannot publish a result. A settled or edited approval is
// marked stale, with no result presented as a current recommendation.
func (d *DB) FinishApprovalAdvisory(ctx context.Context, id int64, lease string, result *approvalreview.Result, errorCode string, stale bool) (bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	src, err := readApprovalAdvisory(ctx, tx, id, true)
	if err != nil {
		return false, err
	}
	if src == nil || src.Advisory == nil || src.Advisory.LeaseID != lease || src.Advisory.State != "running" {
		return false, nil
	}
	a := *src.Advisory
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return false, err
	}
	a.FinishedAt = &now
	a.Result = nil
	switch {
	case stale || src.Status != "pending" || src.Fingerprint() != a.ActionFingerprint:
		a.State, a.ErrorCode = "stale", "snapshot_changed"
	case !now.Before(a.LeaseUntil):
		a.State, a.ErrorCode = "failed", "timeout"
	case errorCode != "":
		switch errorCode {
		case "timeout", "cancelled", "provider_unavailable", "invalid_response", "policy_unavailable":
		default:
			errorCode = "review_failed"
		}
		a.State, a.ErrorCode = "failed", errorCode
	case result == nil:
		a.State, a.ErrorCode = "failed", "invalid_response"
	default:
		raw, err := json.Marshal(result)
		if err != nil {
			return false, err
		}
		valid, err := approvalreview.Parse(string(raw))
		if err != nil {
			return false, err
		}
		a.State, a.Result, a.ErrorCode = "succeeded", &valid, ""
	}
	if err := writeApprovalAdvisory(ctx, tx, id, a); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
