package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	SettingAdvisoryAutoEnabled    = "approval_advisory_auto_enabled"
	SettingAdvisoryAutoConsentAt  = "approval_advisory_auto_consent_at"
	SettingAdvisoryGlobalSlots    = "approval_advisory_global_slots"
	SettingAdvisoryAutoMaxRetries = "approval_advisory_auto_max_retries"
	SettingAdvisoryDailyBudget    = "approval_advisory_daily_budget"
	SettingAdvisoryDailyUsage     = "approval_advisory_daily_usage"
)

const (
	defaultAdvisoryGlobalSlots  = 8
	defaultAdvisoryMaxRetries   = 3
	defaultAdvisoryDailyBudget  = 200
	advisoryAutoBackoffBase     = 30 * time.Second
	advisoryGlobalAdvisoryLockKey = int64(7337741025)
)

// AdvisoryAutoMeta is stored at audit.approval_advisory_auto (not an authorization).
type AdvisoryAutoMeta struct {
	Cancelled   bool       `json:"cancelled,omitempty"`
	Attempts    int        `json:"attempts,omitempty"`
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

// AdvisoryAutoConfig is the resolved operator configuration for background reviews.
type AdvisoryAutoConfig struct {
	Enabled      bool      `json:"enabled"`
	ConsentAt    time.Time `json:"consent_at,omitempty"`
	GlobalSlots  int       `json:"global_slots"`
	MaxRetries   int       `json:"max_retries"`
	DailyBudget  int       `json:"daily_budget"`
	DailyUsed    int       `json:"daily_used"`
	Ready        bool      `json:"ready"`
	ConsentGiven bool      `json:"consent_given"`
}

func (d *DB) advisorySettingInt(key string, def, min, max int) int {
	v, ok, err := d.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// ReadAdvisoryAutoConfig loads background advisory settings and today's usage counter.
func (d *DB) ReadAdvisoryAutoConfig(ctx context.Context) (AdvisoryAutoConfig, error) {
	var out AdvisoryAutoConfig
	out.Enabled = d.GetBool(SettingAdvisoryAutoEnabled, false)
	out.GlobalSlots = d.advisorySettingInt(SettingAdvisoryGlobalSlots, defaultAdvisoryGlobalSlots, 1, 32)
	out.MaxRetries = d.advisorySettingInt(SettingAdvisoryAutoMaxRetries, defaultAdvisoryMaxRetries, 0, 10)
	out.DailyBudget = d.advisorySettingInt(SettingAdvisoryDailyBudget, defaultAdvisoryDailyBudget, 1, 5000)
	if v, ok, _ := d.GetSetting(SettingAdvisoryAutoConsentAt); ok && strings.TrimSpace(v) != "" {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
			out.ConsentAt = t.UTC()
			out.ConsentGiven = true
		}
	}
	used, err := d.advisoryDailyUsed()
	if err != nil {
		return out, err
	}
	out.DailyUsed = used
	out.Ready = out.Enabled && out.ConsentGiven && !out.ConsentAt.IsZero()
	return out, nil
}

type advisoryDailyUsage struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

func (d *DB) advisoryDailyUsed() (int, error) {
	today := time.Now().UTC().Format("2006-01-02")
	raw, ok, err := d.GetSetting(SettingAdvisoryDailyUsage)
	if err != nil {
		return 0, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	var u advisoryDailyUsage
	if json.Unmarshal([]byte(raw), &u) != nil || u.Date != today {
		return 0, nil
	}
	return u.Count, nil
}

// ConsumeAdvisoryDailyBudget reserves one auto-review slot for today.
func (d *DB) ConsumeAdvisoryDailyBudget(ctx context.Context, budget int) (bool, error) {
	if budget <= 0 {
		return false, nil
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	today := time.Now().UTC().Format("2006-01-02")
	var raw sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1 FOR UPDATE`, SettingAdvisoryDailyUsage).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	count := 0
	if raw.Valid && strings.TrimSpace(raw.String) != "" {
		var u advisoryDailyUsage
		if json.Unmarshal([]byte(raw.String), &u) == nil && u.Date == today {
			count = u.Count
		}
	}
	if count >= budget {
		return false, nil
	}
	u := advisoryDailyUsage{Date: today, Count: count + 1}
	encoded, _ := json.Marshal(u)
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES($1,$2)
		ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, SettingAdvisoryDailyUsage, string(encoded)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// SaveAdvisoryAutoConfig persists operator consent-gated configuration.
func (d *DB) SaveAdvisoryAutoConfig(c AdvisoryAutoConfig) error {
	if c.Enabled {
		if c.ConsentAt.IsZero() {
			return errors.New("consent required")
		}
		if err := d.SetSetting(SettingAdvisoryAutoConsentAt, c.ConsentAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	if err := d.SetBool(SettingAdvisoryAutoEnabled, c.Enabled); err != nil {
		return err
	}
	if err := d.SetSetting(SettingAdvisoryGlobalSlots, strconv.Itoa(c.GlobalSlots)); err != nil {
		return err
	}
	if err := d.SetSetting(SettingAdvisoryAutoMaxRetries, strconv.Itoa(c.MaxRetries)); err != nil {
		return err
	}
	return d.SetSetting(SettingAdvisoryDailyBudget, strconv.Itoa(c.DailyBudget))
}

func readAdvisoryAutoMeta(raw []byte) *AdvisoryAutoMeta {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var m AdvisoryAutoMeta
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return &m
}

func (d *DB) ReadAdvisoryAutoMeta(ctx context.Context, id int64) (*AdvisoryAutoMeta, error) {
	var raw []byte
	err := d.QueryRowContext(ctx, `SELECT COALESCE(audit->'approval_advisory_auto','null'::jsonb) FROM intercept_pending WHERE id=$1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return readAdvisoryAutoMeta(raw), nil
}

func writeAdvisoryAutoMeta(ctx context.Context, tx *sql.Tx, id int64, m AdvisoryAutoMeta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE intercept_pending SET audit=jsonb_set(
		COALESCE(NULLIF(audit,'null'::jsonb),'{"approval_advisory_only":true}'::jsonb),'{approval_advisory_auto}',$2::jsonb,true) WHERE id=$1`, id, raw)
	return err
}

// CancelApprovalAdvisoryAuto stops further automatic retries for this pending item.
func (d *DB) CancelApprovalAdvisoryAuto(ctx context.Context, id int64) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT status FROM intercept_pending WHERE id=$1 FOR UPDATE`, id).Scan(new(string)); err != nil {
		return err
	}
	if err := writeAdvisoryAutoMeta(ctx, tx, id, AdvisoryAutoMeta{Cancelled: true}); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordAdvisoryAutoFailure schedules a bounded retry or marks exhaustion in auto meta.
func (d *DB) RecordAdvisoryAutoFailure(ctx context.Context, id int64, code string, maxRetries int) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(audit->'approval_advisory_auto','null'::jsonb) FROM intercept_pending WHERE id=$1 FOR UPDATE`, id).Scan(&raw); err != nil {
		return err
	}
	meta := AdvisoryAutoMeta{}
	if m := readAdvisoryAutoMeta(raw); m != nil {
		meta = *m
	}
	if meta.Cancelled {
		return tx.Commit()
	}
	meta.Attempts++
	meta.LastError = code
	if meta.Attempts <= maxRetries {
		backoff := advisoryAutoBackoffBase * time.Duration(1<<(meta.Attempts-1))
		if backoff > 10*time.Minute {
			backoff = 10 * time.Minute
		}
		t := time.Now().UTC().Add(backoff)
		meta.NextRetryAt = &t
	} else {
		meta.NextRetryAt = nil
	}
	if err := writeAdvisoryAutoMeta(ctx, tx, id, meta); err != nil {
		return err
	}
	return tx.Commit()
}

// ListPendingIDsForAutoAdvisory returns pending intercept ids oldest first (FIFO).
func (d *DB) ListPendingIDsForAutoAdvisory(ctx context.Context, limit int) ([]int64, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `SELECT id FROM intercept_pending WHERE status='pending' ORDER BY created_at ASC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// TryAdvisoryGlobalSlot acquires one cross-process advisory slot. A dedicated pooled
// connection holds the lock until release — required because advisory locks are per session.
func (d *DB) TryAdvisoryGlobalSlot(ctx context.Context, slots int) (release func(), ok bool, err error) {
	if slots <= 0 {
		slots = defaultAdvisoryGlobalSlots
	}
	conn, err := d.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	for i := 0; i < slots; i++ {
		key := advisoryGlobalAdvisoryLockKey + int64(i)
		var locked bool
		if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&locked); err != nil {
			conn.Close()
			return nil, false, err
		}
		if !locked {
			continue
		}
		return func() {
			_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
			conn.Close()
		}, true, nil
	}
	conn.Close()
	return nil, false, nil
}
