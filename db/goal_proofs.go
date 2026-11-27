package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// FindingStatusProvesGoal preserves the planner's existing evidence policy.
// An empty status represents a legacy finding node without a standalone row.
func FindingStatusProvesGoal(status string) bool {
	return status == "" || status == FindingConfirmed
}

type GoalProofResult struct {
	GoalCount   int
	AllGoalsMet bool
}

// ProveGoal validates and records a proof in one transaction. Source nodes are
// locked before goals, the same order used when invalidating evidence. Do not
// lock the standalone finding here: triage/deletion already locks that row
// before the source node, so taking the reverse order would deadlock. Its status
// is read after the source lock; a concurrent triage writer must acquire that
// same source lock before removing proofs and can therefore never miss this one.
func (s *ExplorationStore) ProveGoal(ctx context.Context, goalID, evidenceID int64) (out GoalProofResult, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var kind, evidenceState string
	err = tx.QueryRowContext(ctx, `SELECT node.kind,node.state FROM exploration_nodes node
WHERE node.id=$2 AND node.kind IN ('fact','finding') AND (
 node.exploration_id=$1 OR EXISTS (
  SELECT 1 FROM tasks owner
  JOIN task_relations relation ON relation.task_id=owner.id
  JOIN tasks source ON source.id=relation.source_task_id AND source.deleted_at IS NULL
  WHERE owner.exploration_id=$1 AND owner.deleted_at IS NULL
    AND source.exploration_id=node.exploration_id
 )) FOR UPDATE OF node`, s.expID, evidenceID).Scan(&kind, &evidenceState)
	if errors.Is(err, sql.ErrNoRows) {
		return out, errors.New("evidence_id 必须是本任务或直接关联任务的事实/漏洞节点")
	}
	if err != nil {
		return out, err
	}
	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM exploration_nodes
WHERE id=$1 AND exploration_id=$2 AND kind='goal' FOR UPDATE`, goalID, s.expID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return out, errors.New("goal_id 必须是本任务的目标节点（关联任务目标只读）")
	}
	if err != nil {
		return out, err
	}
	if kind == KindFinding {
		var status string
		var count int
		var proven bool
		err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(bool_and(status IN ('','confirmed')),true),
COALESCE(string_agg(DISTINCT status,','),'') FROM findings WHERE node_id=$1`, evidenceID).Scan(&count, &proven, &status)
		if err != nil {
			return out, err
		}
		if count == 0 && evidenceState == "dismissed" {
			return out, errors.New("漏洞记录已删除或撤回，不能作为目标达成证据")
		}
		// node_id is not unique in legacy/imported data. Never accept an arbitrary
		// confirmed row when another row for this same node revokes its evidence.
		if !proven {
			return out, fmt.Errorf("该漏洞尚未验证通过(当前状态 %s),不能作为目标达成证据;待反证验证确认为 confirmed 后再试", status)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
VALUES($1,$2,'proves',$3) ON CONFLICT(exploration_id,src_id,rel,dst_id) DO NOTHING`, s.expID, evidenceID, goalID); err != nil {
		return out, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='met',blocked_reason=NULL,
content_version=content_version+1 WHERE id=$1 AND state<>'met'`, goalID); err != nil {
		return out, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(bool_and(state='met'),false)
FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal'`, s.expID).Scan(&out.GoalCount, &out.AllGoalsMet); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// discardGoalProofsTx removes proof links when their source evidence is revoked
// or deleted. Callers perform the evidence mutation in this same transaction.
// Callers may already hold a finding row. Do not acquire sibling finding rows:
// node_id is not unique and two such transitions would invert their row locks.
// Bulk node deletions/reconciliation lock their full finding set first instead.
// Lock order is finding rows -> source nodes -> goals, with IDs sorted within
// each set. ProveGoal never locks finding rows. Source locks are acquired BEFORE
// reading edges so proofs committed by a concurrent prover cannot be missed.
func discardGoalProofsTx(ctx context.Context, tx *sql.Tx, sourceIDs []int64) error {
	return discardGoalProofsMatchingTx(ctx, tx, sourceIDs, false)
}

const invalidFindingProofCondition = `(EXISTS (
 SELECT 1 FROM findings finding WHERE finding.node_id=source.id AND finding.status NOT IN ('','confirmed')
) OR (source.state='dismissed' AND NOT EXISTS (SELECT 1 FROM findings finding WHERE finding.node_id=source.id)))`

func discardGoalProofsMatchingTx(ctx context.Context, tx *sql.Tx, sourceIDs []int64, invalidOnly bool) error {
	if len(sourceIDs) == 0 {
		return nil
	}
	if invalidOnly {
		if err := lockProofFindingRowsTx(ctx, tx, sourceIDs); err != nil {
			return err
		}
	}
	if _, err := proofIDsTx(ctx, tx, `SELECT id FROM exploration_nodes
WHERE id=ANY($1::bigint[]) AND kind IN ('fact','finding') ORDER BY id FOR UPDATE`, sourceIDs); err != nil {
		return err
	}
	if invalidOnly {
		// Candidates may have been re-confirmed while waiting for these locks.
		// Re-check now; selecting candidates alone must never revoke valid proof.
		var err error
		sourceIDs, err = proofIDsTx(ctx, tx, `SELECT source.id FROM exploration_nodes source
WHERE source.id=ANY($1::bigint[]) AND source.kind='finding' AND `+invalidFindingProofCondition, sourceIDs)
		if err != nil {
			return err
		}
	}
	goals, err := proofIDsTx(ctx, tx, `SELECT goal.id FROM exploration_nodes goal
WHERE goal.kind='goal' AND EXISTS (SELECT 1 FROM exploration_edges edge
 WHERE edge.src_id=ANY($1::bigint[]) AND edge.dst_id=goal.id AND edge.rel='proves')
ORDER BY goal.id FOR UPDATE OF goal`, sourceIDs)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM exploration_edges
WHERE src_id=ANY($1::bigint[]) AND rel='proves'`, sourceIDs); err != nil {
		return err
	}
	// Only goals whose tracked proof was removed are eligible for reopening.
	// Manual/legacy met goals without tracked proof are deliberately untouched.
	_, err = tx.ExecContext(ctx, `UPDATE exploration_nodes goal
SET state='open',blocked_reason=NULL,content_version=content_version+1
WHERE goal.id=ANY($1::bigint[]) AND goal.state='met' AND NOT EXISTS (
 SELECT 1 FROM exploration_edges edge JOIN exploration_nodes source ON source.id=edge.src_id
 WHERE edge.dst_id=goal.id AND edge.rel='proves' AND (
  source.kind='fact' OR (source.kind='finding' AND NOT `+invalidFindingProofCondition+`)
 ))`, goals)
	return err
}

func lockProofFindingRowsTx(ctx context.Context, tx *sql.Tx, sourceIDs []int64) error {
	_, err := proofIDsTx(ctx, tx, `SELECT id FROM findings WHERE node_id=ANY($1::bigint[]) ORDER BY id FOR UPDATE`, sourceIDs)
	return err
}

func discardDeletedNodeProofsTx(ctx context.Context, tx *sql.Tx, sourceIDs []int64) error {
	// Node deletion updates every referencing finding's FK, including duplicate
	// legacy rows. Acquire those rows before the source lock, not during CASCADE.
	if err := lockProofFindingRowsTx(ctx, tx, sourceIDs); err != nil {
		return err
	}
	return discardGoalProofsTx(ctx, tx, sourceIDs)
}

// Node deletion's FK cascade needs an anchors mutation lock. Acquire it before
// source/goal row locks: a dependent task's prepared deletion can otherwise hold
// the anchors table while waiting for a goal whose proof we are invalidating.
// Keep any existing task lock first, matching task deletion's established order.
func lockNodeDeletionAnchorsTx(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `LOCK TABLE exploration_anchors IN ROW EXCLUSIVE MODE`)
	return err
}

func proofIDsTx(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func discardExplorationGoalProofsTx(ctx context.Context, tx *sql.Tx, explorationID int64) error {
	if err := lockNodeDeletionAnchorsTx(ctx, tx); err != nil {
		return err
	}
	ids, err := proofIDsTx(ctx, tx, `SELECT id FROM exploration_nodes
WHERE exploration_id=$1 AND kind IN ('fact','finding') ORDER BY id`, explorationID)
	if err != nil {
		return err
	}
	return discardDeletedNodeProofsTx(ctx, tx, ids)
}

// reconcileFindingGoalProofsTx repairs stale proofs from older versions and
// imported archives. It selects explicitly invalid finding rows and dismissed
// tombstones; facts, valid synthetic findings and manual decisions stay intact.
// explorationID=0 means all explorations (startup); otherwise repair one restore.
func reconcileFindingGoalProofsTx(ctx context.Context, tx *sql.Tx, explorationID int64) error {
	ids, err := proofIDsTx(ctx, tx, `SELECT source.id FROM exploration_nodes source
WHERE source.kind='finding' AND ($1::bigint=0 OR source.exploration_id=$1)
AND EXISTS (SELECT 1 FROM exploration_edges edge WHERE edge.src_id=source.id AND edge.rel='proves')
AND `+invalidFindingProofCondition+` ORDER BY source.id`, explorationID)
	if err != nil {
		return err
	}
	return discardGoalProofsMatchingTx(ctx, tx, ids, true)
}
