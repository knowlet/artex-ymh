package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/approvalreview"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
)

type approvalAdvisoryAPI struct {
	s *Server
}

// registerApprovalAdvisoryRoutes registers authenticated, explicit-consent
// consultation endpoints. The service has no reference to Interceptor.Decide.
func (s *Server) registerApprovalAdvisoryRoutes(mux *http.ServeMux) {
	a := &approvalAdvisoryAPI{s: s}
	mux.HandleFunc("GET /api/intercept/pending/{id}/advisory", a.get)
	mux.HandleFunc("POST /api/intercept/pending/{id}/advisory", a.post)
	mux.HandleFunc("POST /api/intercept/pending/{id}/advisory/cancel", a.cancelAuto)
	mux.HandleFunc("GET /api/intercept/advisory-auto", s.interceptGetAdvisoryAuto)
	mux.HandleFunc("PUT /api/intercept/advisory-auto", s.interceptSetAdvisoryAuto)
}

type advisoryPreparation struct {
	input          []byte
	fingerprint    string
	profileID      int64
	model          string
	profileVersion string
	streaming      bool
	timeout        time.Duration
}

// advisoryRows bounds both transferred values and total prompt data; overflowing
// policies fail rather than silently truncate away a restrictive rule.
func advisoryRows(ctx context.Context, pg *db.DB, query string, args ...any) ([]json.RawMessage, error) {
	rows, err := pg.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	total := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, db.ErrAdvisoryTooLarge
		}
		total += len(raw)
		if len(out) >= 200 || total > 32<<10 {
			return nil, db.ErrAdvisoryTooLarge
		}
		out = append(out, json.RawMessage(raw))
	}
	return out, rows.Err()
}

func prepareApprovalAdvisory(ctx context.Context, pg *db.DB, src *db.ApprovalAdvisorySource) (advisoryPreparation, error) {
	var out advisoryPreparation
	settings := map[string]string{}
	rows, err := pg.QueryContext(ctx, `SELECT key,CASE WHEN octet_length(value)<=16384 THEN value END FROM settings
		WHERE key IN ('llm_judge_profile_id','llm_judge_prompt','llm_judge_timeout_seconds',
		'llm_judge_enabled','llm_judge_fail_action','llm_judge_ask_timeout_seconds',
		'llm_judge_ask_timeout_action','roe_enforcement','intercept_enabled_tools','guard_auto_allow') ORDER BY key`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var key string
		var value sql.NullString
		if err = rows.Scan(&key, &value); err != nil {
			break
		}
		if !value.Valid {
			err = db.ErrAdvisoryTooLarge
			break
		}
		settings[key] = value.String
	}
	rowsErr := rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if rowsErr != nil {
		return out, rowsErr
	}
	if value := strings.TrimSpace(settings["llm_judge_profile_id"]); value != "" {
		out.profileID, err = strconv.ParseInt(value, 10, 64)
		if err != nil || out.profileID < 0 {
			return out, errors.New("invalid judge selection")
		}
	}
	// Explicit invalid/deleted profiles do not fall back to a different model.
	query := `SELECT id,model,streaming,updated_at::text FROM llm_profiles WHERE id=$1`
	args := []any{out.profileID}
	if out.profileID == 0 {
		query = `SELECT id,model,streaming,updated_at::text FROM llm_profiles WHERE is_default ORDER BY id LIMIT 1`
		args = nil
	}
	err = pg.QueryRowContext(ctx, query, args...).Scan(&out.profileID, &out.model, &out.streaming, &out.profileVersion)
	if err != nil {
		return out, err
	}
	if len(out.model) > 1024 {
		return out, db.ErrAdvisoryTooLarge
	}
	timeout := 15
	if value := strings.TrimSpace(settings["llm_judge_timeout_seconds"]); value != "" {
		timeout, err = strconv.Atoi(value)
		if err != nil {
			return out, err
		}
	}
	out.timeout = time.Duration(max(1, min(timeout, 60))) * time.Second
	policy := map[string]any{"matched_rule_id": src.RuleID, "settings": settings, "scope_is_declaration_not_authorization_proof": true, "recorded_context_available": false}
	rules, err := advisoryRows(ctx, pg, `SELECT CASE WHEN octet_length(row_to_json(r)::text)<=16384 THEN row_to_json(r) END
		FROM (SELECT id,name,enabled,priority,match_target,match_type,pattern,action,message,
		timeout_enabled,timeout_seconds,timeout_action,builtin FROM intercept_rules ORDER BY priority DESC,id LIMIT 201) r`)
	if err != nil {
		return out, err
	}
	policy["rules"] = rules
	if src.TaskID != "" {
		taskID, err := strconv.ParseInt(src.TaskID, 10, 64)
		if err != nil || taskID <= 0 {
			return out, errors.New("task scope unavailable")
		}
		var expID int64
		if err = pg.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1`, taskID).Scan(&expID); err != nil {
			return out, err
		}
		scope, err := advisoryRows(ctx, pg, `SELECT CASE WHEN octet_length(row_to_json(r)::text)<=16384 THEN row_to_json(r) END
			FROM (SELECT id,kind,company_id,domain,net::text,value,source,reason FROM task_scope WHERE task_id=$1 ORDER BY id LIMIT 201) r`, taskID)
		if err != nil {
			return out, err
		}
		policy["task_scope"] = scope
		constraints, err := advisoryRows(ctx, pg, `SELECT CASE WHEN octet_length(row_to_json(r)::text)<=16384 THEN row_to_json(r) END
			FROM (SELECT id,kind,text,origin FROM task_constraints WHERE exploration_id=$1 ORDER BY id LIMIT 201) r`, expID)
		if err != nil {
			return out, err
		}
		policy["constraints"] = constraints
	}
	// Only v4's explicitly selected context is forwarded. Raw transcripts,
	// legacy scheduler context and previous advisory answers are never included.
	var recorded intercept.ReviewInput
	if json.Unmarshal(src.ModelInput, &recorded) == nil && recorded.Version == 4 && recorded.Tool == src.Tool && sameAdvisoryJSON(recorded.Arguments, src.Input) {
		if recorded.Background != nil && recorded.Background.Source != intercept.BackgroundUserMessage {
			recorded.Background = nil
		}
		policy["recorded_context_available"] = true
		policy["working_directory"] = recorded.WorkingDir
		policy["selected_background"] = recorded.Background
	}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		return out, err
	}
	in := approvalreview.Input{PendingID: src.ID, Tool: src.Tool, Arguments: src.Input, Reason: src.Reason,
		Policy: policyRaw, ProfileID: out.profileID, ProfileVersion: out.profileVersion}
	out.input, out.fingerprint, err = in.Encode()
	return out, err
}

func sameAdvisoryJSON(a, b []byte) bool {
	canonical := func(raw []byte) ([]byte, error) {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		return json.Marshal(v)
	}
	x, err := canonical(a)
	if err != nil {
		return false
	}
	y, err := canonical(b)
	return err == nil && bytes.Equal(x, y)
}

func (a *approvalAdvisoryAPI) source(w http.ResponseWriter, r *http.Request) (*db.ApprovalAdvisorySource, bool) {
	w.Header().Set("Cache-Control", "no-store")
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "審批編號無效")
		return nil, false
	}
	pg := a.s.pg(w)
	if pg == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	src, err := pg.ReadApprovalAdvisory(ctx, id)
	if err != nil {
		writeErr(w, 503, "無法讀取有界的審批快照；未變更審批結果")
		return nil, false
	}
	if src == nil {
		writeErr(w, 404, "找不到審批紀錄")
		return nil, false
	}
	return src, true
}

func advisoryView(src *db.ApprovalAdvisorySource, current bool, auto *db.AdvisoryAutoMeta, autoCfg db.AdvisoryAutoConfig) map[string]any {
	out := map[string]any{"pending_id": src.ID, "approval_status": src.Status, "advisory_only": true, "current": false, "assessment": nil,
		"auto_enabled": autoCfg.Ready, "auto_cancelled": auto != nil && auto.Cancelled, "auto_queued": false}
	if autoCfg.Ready && src.Status == "pending" && (auto == nil || !auto.Cancelled) {
		if src.Advisory == nil || (src.Advisory.State == "failed" && auto != nil && auto.NextRetryAt != nil && time.Now().Before(*auto.NextRetryAt)) {
			out["auto_queued"] = src.Advisory == nil || src.Advisory.State != "running"
		}
	}
	if src.Advisory == nil {
		return out
	}
	r := src.Advisory
	state, code := r.State, r.ErrorCode
	if state == "running" && time.Now().After(r.LeaseUntil) {
		state, code = "failed", "interrupted"
	}
	out["current"] = current && src.Status == "pending" && state == "succeeded"
	out["assessment"] = map[string]any{"state": state, "trigger": r.Trigger, "fingerprint": r.Fingerprint, "profile_id": r.ProfileID,
		"model": r.Model, "started_at": r.StartedAt, "finished_at": r.FinishedAt, "lease_until": r.LeaseUntil,
		"error_code": code, "result": r.Result}
	if auto != nil {
		out["auto_meta"] = map[string]any{"attempts": auto.Attempts, "next_retry_at": auto.NextRetryAt, "last_error": auto.LastError}
	}
	return out
}

func (a *approvalAdvisoryAPI) get(w http.ResponseWriter, r *http.Request) {
	src, ok := a.source(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	current := false
	if src.Advisory != nil && src.Advisory.State == "succeeded" && src.Status == "pending" {
		prep, err := prepareApprovalAdvisory(ctx, a.s.m.pg, src)
		current = err == nil && prep.fingerprint == src.Advisory.Fingerprint && src.Fingerprint() == src.Advisory.ActionFingerprint
	}
	auto, _ := a.s.m.pg.ReadAdvisoryAutoMeta(ctx, src.ID)
	autoCfg, _ := a.s.m.pg.ReadAdvisoryAutoConfig(ctx)
	writeJSON(w, 200, advisoryView(src, current, auto, autoCfg))
}

func (a *approvalAdvisoryAPI) post(w http.ResponseWriter, r *http.Request) {
	src, ok := a.source(w, r)
	if !ok {
		return
	}
	if src.Status != "pending" {
		writeErr(w, 409, "審批已結束；不再呼叫模型")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil {
		writeErr(w, 413, "審查請求過大")
		return
	}
	if text := strings.TrimSpace(string(raw)); text != "" && text != "{}" {
		writeErr(w, 400, "審查僅接受既有紀錄，不接受替換命令或模型參數")
		return
	}
	res, err := a.s.runApprovalAdvisoryReview(r.Context(), src.ID, "manual")
	if err != nil {
		a.writeAdvisoryErr(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	auto, _ := a.s.m.pg.ReadAdvisoryAutoMeta(ctx, src.ID)
	autoCfg, _ := a.s.m.pg.ReadAdvisoryAutoConfig(ctx)
	status := res.http
	if status == 0 {
		status = http.StatusOK
	}
	writeJSON(w, status, advisoryView(res.src, res.current, auto, autoCfg))
}

func (a *approvalAdvisoryAPI) cancelAuto(w http.ResponseWriter, r *http.Request) {
	src, ok := a.source(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := a.s.m.pg.CancelApprovalAdvisoryAuto(ctx, src.ID); err != nil {
		writeErr(w, 503, "無法取消自動審查")
		return
	}
	auto, _ := a.s.m.pg.ReadAdvisoryAutoMeta(ctx, src.ID)
	autoCfg, _ := a.s.m.pg.ReadAdvisoryAutoConfig(ctx)
	writeJSON(w, 200, advisoryView(src, false, auto, autoCfg))
}

func (a *approvalAdvisoryAPI) writeAdvisoryErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAdvisoryNotFound):
		writeErr(w, 404, "找不到審批紀錄")
	case errors.Is(err, errAdvisorySettled):
		writeErr(w, 409, "審批已結束；不再呼叫模型")
	case errors.Is(err, errAdvisoryBusy):
		writeErr(w, 429, "審查忙碌中；請稍後手動重試")
	case errors.Is(err, db.ErrAdvisoryNotPending), errors.Is(err, db.ErrAdvisoryChanged):
		writeErr(w, 409, "審批已結束或內容改變")
	case errors.Is(err, errAdvisoryBudget):
		writeErr(w, 429, "已達今日自動審查上限")
	default:
		writeErr(w, 503, "裁判模型或政策快照不可用；未變更審批結果")
	}
}

func (s *Server) interceptGetAdvisoryAuto(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	cfg, err := pg.ReadAdvisoryAutoConfig(r.Context())
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) interceptSetAdvisoryAuto(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req db.AdvisoryAutoConfig
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Enabled && req.ConsentAt.IsZero() {
		writeErr(w, 400, "啟用背景審查前必須確認資料外送同意")
		return
	}
	if req.GlobalSlots <= 0 {
		req.GlobalSlots = 8
	}
	if req.MaxRetries < 0 {
		req.MaxRetries = 3
	}
	if req.DailyBudget <= 0 {
		req.DailyBudget = 200
	}
	if err := pg.SaveAdvisoryAutoConfig(req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg, err := pg.ReadAdvisoryAutoConfig(r.Context())
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func runApprovalAdvisory(ctx context.Context, prov llm.Provider, input []byte, streaming bool) (approvalreview.Result, error) {
	invalid := errors.New("invalid advisory completion")
	if len(input) > approvalreview.MaxInputBytes {
		return approvalreview.Result{}, invalid
	}
	temp := 0.0
	req := llm.CompletionRequest{System: []string{approvalreview.Prompt}, Messages: []llm.Message{llm.UserText(string(input))},
		MaxTokens: 1536, Temperature: &temp, Thinking: "disabled"}
	var text strings.Builder
	if streaming {
		complete := false
		stopReason := ""
		for ev, err := range prov.Stream(ctx, req) {
			if ctx.Err() != nil {
				return approvalreview.Result{}, ctx.Err()
			}
			if err != nil {
				return approvalreview.Result{}, err
			}
			if complete {
				return approvalreview.Result{}, invalid
			}
			switch ev.Type {
			case llm.SEToolUseStart, llm.SEToolInputJSON:
				return approvalreview.Result{}, invalid
			case llm.SETextDelta:
				if text.Len()+len(ev.Text) > approvalreview.MaxOutputBytes {
					return approvalreview.Result{}, invalid
				}
				text.WriteString(ev.Text)
			case llm.SEMessageDelta:
				if ev.StopReason != "" {
					stopReason = ev.StopReason
				}
			case llm.SEMessageStop:
				complete = true
			}
		}
		if !complete || stopReason != "end_turn" && stopReason != "stop" {
			return approvalreview.Result{}, invalid
		}
	} else {
		msg, reason, _, err := prov.Complete(ctx, req)
		if ctx.Err() != nil {
			return approvalreview.Result{}, ctx.Err()
		}
		if err != nil {
			return approvalreview.Result{}, err
		}
		if len(msg.ToolUses()) > 0 || reason != "end_turn" && reason != "stop" {
			return approvalreview.Result{}, invalid
		}
		for _, b := range msg.Content {
			if text.Len()+len(b.Text) > approvalreview.MaxOutputBytes {
				return approvalreview.Result{}, invalid
			}
			text.WriteString(b.Text)
		}
	}
	if ctx.Err() != nil {
		return approvalreview.Result{}, ctx.Err()
	}
	return approvalreview.Parse(text.String())
}
