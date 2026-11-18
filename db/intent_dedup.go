package db

import (
	"database/sql"
	"encoding/json"
)

// AddIntentWithParents admits exact duplicate active work once per exploration.
// Payload, asset set, parent-evidence set and origin must all match. Priority is
// scheduling metadata: a duplicate cannot reset state, cooldown or retry budget.
// Paused work is included so planner repetition cannot bypass manual controls.
// Planner repeats also reuse terminal work; explicit human reruns use ReopenIntent.
type IntentAdmission struct {
	ID     int64  `json:"id"`
	State  string `json:"state"`
	Reused bool   `json:"reused"`
}

func (s *ExplorationStore) AddIntentWithParents(payload map[string]any, priority int, anchors []int64, origin string, parents []int64) (int64, error) {
	out, err := s.AdmitIntentWithParents(payload, priority, anchors, origin, parents)
	return out.ID, err
}
func (s *ExplorationStore) AdmitIntentWithParents(payload map[string]any, priority int, anchors []int64, origin string, parents []int64) (IntentAdmission, error) {
	if origin == "" {
		origin = "planner"
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return IntentAdmission{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return IntentAdmission{}, err
	}
	defer tx.Rollback()
	// Serialize admission across processes, including the no-match/first-insert
	// case. NO KEY UPDATE stays compatible with the foreign-key KEY SHARE locks
	// held by independent graph writes. A statement after this lock sees the prior commit.
	var exp int64
	if err := tx.QueryRow(`SELECT id FROM explorations WHERE id=$1 FOR NO KEY UPDATE`, s.expID).Scan(&exp); err != nil {
		return IntentAdmission{}, err
	}
	var id int64
	var state string
	err = tx.QueryRow(`SELECT n.id, n.state FROM exploration_nodes n
WHERE n.exploration_id=$1 AND n.kind='intent' AND (n.state IN ('open','running','paused') OR $3='planner')
  AND (n.payload - 'asset_ids')=($2::jsonb - 'asset_ids') AND n.origin=$3
  AND ARRAY(SELECT a.asset_id FROM exploration_anchors a WHERE a.node_id=n.id ORDER BY a.asset_id)
      = ARRAY(SELECT DISTINCT unnest($4::bigint[]) ORDER BY 1)
  AND ARRAY(SELECT e.src_id FROM exploration_edges e WHERE e.exploration_id=$1 AND e.dst_id=n.id AND e.rel=$6 ORDER BY e.src_id)
      = ARRAY(SELECT DISTINCT unnest($5::bigint[]) ORDER BY 1)
ORDER BY CASE WHEN n.state IN ('open','running','paused') THEN 0 ELSE 1 END, n.id LIMIT 1`, s.expID, string(raw), origin, anchors, parents, RelDerivedFrom).Scan(&id, &state)
	if err == nil {
		return IntentAdmission{ID: id, State: state, Reused: true}, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return IntentAdmission{}, err
	}
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
VALUES($1,'intent',$2,$3,'open',$4) RETURNING id`, s.expID, string(raw), priority, origin).Scan(&id); err != nil {
		return IntentAdmission{}, err
	}
	for _, asset := range anchors {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, asset); err != nil {
			return IntentAdmission{}, err
		}
	}
	for _, parent := range parents {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, s.expID, parent, RelDerivedFrom, id); err != nil {
			return IntentAdmission{}, err
		}
	}
	return IntentAdmission{ID: id, State: "open"}, tx.Commit()
}

// FollowedFactIDs reads coverage without the graph overview's history window.
// A terminal child still records that this evidence has already been followed.
func (s *ExplorationStore) FollowedFactIDs(ids []int64) (map[int64]bool, error) {
	out := make(map[int64]bool)
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(`SELECT DISTINCT e.src_id FROM exploration_edges e
 JOIN exploration_nodes n ON n.id=e.dst_id AND n.exploration_id=e.exploration_id
 WHERE e.exploration_id=$1 AND e.rel=$2 AND n.kind='intent' AND e.src_id=ANY($3::bigint[])`, s.expID, RelDerivedFrom, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
