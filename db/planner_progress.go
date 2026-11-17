package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
)

// PlannerProgress is a persisted graph snapshot, not a count of attempted tool
// calls. IntentIDs includes completed intents so a fast worker completing before
// the planner returns still counts as progress, but excludes cancelled/deleted
// work. IDs are compared as a set: sequence allocation is not commit order.
type PlannerProgress struct {
	IntentIDs     []int64 `json:"intent_ids"`
	ActiveIntents int     `json:"active_intents"`
	OpenGoalIDs   []int64 `json:"open_goal_ids"`
	MetGoalIDs    []int64 `json:"met_goal_ids"`
}

func (p PlannerProgress) NeedsWork() bool { return len(p.OpenGoalIDs) > 0 && p.ActiveIntents == 0 }

// AdvancedFrom recognizes only committed work or a newly proven goal. An
// already-met goal being proved again, failed writes, reads and prose do not count.
func (p PlannerProgress) AdvancedFrom(before PlannerProgress) bool {
	for _, id := range p.IntentIDs {
		if _, found := slices.BinarySearch(before.IntentIDs, id); !found {
			return true
		}
	}
	for _, id := range p.MetGoalIDs {
		if slices.Contains(before.OpenGoalIDs, id) {
			return true
		}
	}
	return false
}

type plannerProgressQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readPlannerProgress(ctx context.Context, q plannerProgressQuerier, expID int64) (p PlannerProgress, err error) {
	var intents, open, met []byte
	err = q.QueryRowContext(ctx, `SELECT
		COALESCE(jsonb_agg(id ORDER BY id) FILTER (WHERE kind='intent' AND state NOT IN ('deleted','stopped')), '[]'::jsonb),
		COUNT(*) FILTER (WHERE kind='intent' AND state IN ('open','running')),
		COALESCE(jsonb_agg(id ORDER BY id) FILTER (WHERE kind='goal' AND state='open'), '[]'::jsonb),
		COALESCE(jsonb_agg(id ORDER BY id) FILTER (WHERE kind='goal' AND state='met'), '[]'::jsonb)
		FROM exploration_nodes WHERE exploration_id=$1 AND kind IN ('intent','goal')`, expID).
		Scan(&intents, &p.ActiveIntents, &open, &met)
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(intents, &p.IntentIDs); err != nil {
		return p, err
	}
	if err = json.Unmarshal(open, &p.OpenGoalIDs); err != nil {
		return p, err
	}
	err = json.Unmarshal(met, &p.MetGoalIDs)
	return p, err
}

func (s *ExplorationStore) PlannerProgress(ctx context.Context) (PlannerProgress, error) {
	return readPlannerProgress(ctx, s.db, s.expID)
}

type plannerProgressCheckpoint struct {
	IntentIDs         []int64 `json:"intent_ids"`
	OpenGoalIDs       []int64 `json:"open_goal_ids"`
	ConsecutiveStalls int     `json:"consecutive_stalls"`
}

// PlannerStallReport describes the liveness check recorded for a planning round.
// HintID is nonzero only when a new escalation was inserted, not on every repeat.
type PlannerStallReport struct {
	ConsecutiveStalls int
	HintID            int64
}

// FinishPlannerProgress serializes the durable stall counter and warning
// deduplication with the exploration row. It rechecks committed graph state in
// the transaction, so newly observed worker/main-agent progress suppresses a stale
// conclusion. Node changes after this read are reconciled on the next round; the
// row lock only serializes monitor checkpoints, not all graph writes. No LLM call,
// intent generation or task transition occurs.
func (s *ExplorationStore) FinishPlannerProgress(ctx context.Context, before PlannerProgress, stalled bool, threshold, maxTurns int, terminalReason string) (report PlannerStallReport, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT planner_progress FROM explorations WHERE id=$1 FOR UPDATE`, s.expID).Scan(&raw); err != nil {
		return report, err
	}
	var previous plannerProgressCheckpoint
	if err = json.Unmarshal(raw, &previous); err != nil {
		return report, fmt.Errorf("read planner progress checkpoint: %w", err)
	}
	current, err := readPlannerProgress(ctx, tx, s.expID)
	if err != nil {
		return report, err
	}
	stalled = stalled && current.NeedsWork() && !current.AdvancedFrom(before)
	if threshold < 1 {
		threshold = 1
	}
	checkpoint := plannerProgressCheckpoint{IntentIDs: current.IntentIDs, OpenGoalIDs: current.OpenGoalIDs}
	if stalled {
		checkpoint.ConsecutiveStalls = 1
		if slices.Equal(previous.IntentIDs, current.IntentIDs) && slices.Equal(previous.OpenGoalIDs, current.OpenGoalIDs) {
			// Once escalated, retain the threshold rather than grow an unbounded
			// counter. Messages deliberately say "at least" after this point.
			checkpoint.ConsecutiveStalls = min(previous.ConsecutiveStalls, threshold-1) + 1
		}
	}
	report.ConsecutiveStalls = checkpoint.ConsecutiveStalls
	encoded, err := json.Marshal(checkpoint)
	if err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE explorations SET planner_progress=$2 WHERE id=$1`, s.expID, string(encoded)); err != nil {
		return report, err
	}
	if !stalled || (previous.ConsecutiveStalls > 0 && checkpoint.ConsecutiveStalls == 1) {
		// Resolve the previous episode once real work/goals advance, including work
		// that appeared and finished between two planning rounds.
		if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='consumed'
			WHERE exploration_id=$1 AND kind='hint' AND origin='scheduler' AND state='active'
			AND payload->>'kind'='planner_stalled'`, s.expID); err != nil {
			return report, err
		}
	}
	if checkpoint.ConsecutiveStalls >= threshold {
		message := fmt.Sprintf("【规划停滞】连续至少 %d 轮心跳后仍无新意图或已证明的目标，且没有 open/running 意图。请检查规划器最后的 tool_result、模型/网关工具调用格式及 agents.max_turns（当前 %d；0 为不限），确认约束与可用证据后由人工调整方向或补充提示；系统不会虚构意图或绕过审批。", checkpoint.ConsecutiveStalls, maxTurns)
		payload, _ := json.Marshal(map[string]any{"kind": "planner_stalled", "text": message,
			"consecutive_stalls": checkpoint.ConsecutiveStalls, "max_turns": maxTurns, "terminal_reason": terminalReason})
		err = tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
			SELECT $1,'hint',$2,0,'active','scheduler'
			WHERE NOT EXISTS (SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='hint'
				AND origin='scheduler' AND state='active' AND payload->>'kind'='planner_stalled')
			RETURNING id`, s.expID, string(payload)).Scan(&report.HintID)
		if err != nil && err != sql.ErrNoRows {
			return report, err
		}
	}
	err = tx.Commit()
	return report, err
}
