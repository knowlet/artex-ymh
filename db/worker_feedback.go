package db

import (
	"database/sql"
	"encoding/json"
	"unicode/utf8"
)

const (
	workerFeedbackIntentLimit   = 6
	workerFeedbackActivityLimit = 128
	workerFeedbackToolLimit     = 8
	workerFeedbackErrorLimit    = 3
	workerFeedbackOutputRunes   = 800
	workerFeedbackErrorRunes    = 240
	workerFeedbackToolRunes     = 128
)

// Each branch uses idx_act_worker_output to find a final result or fallback
// text without scanning the oldest activity page. A result retains precedence
// over a newer text row, matching the existing get_worker_output contract.
// n is an intent row already authorized by the enclosing query.
const latestWorkerOutputQuery = `
SELECT candidate.* FROM (
  (SELECT a.id, a.kind, a.is_error, a.summary, a.detail
   FROM activity a WHERE a.exploration_id=n.exploration_id AND a.node_id=n.id AND a.kind='result'
   ORDER BY a.id DESC LIMIT 1)
  UNION ALL
  (SELECT a.id, a.kind, a.is_error, a.summary, a.detail
   FROM activity a WHERE a.exploration_id=n.exploration_id AND a.node_id=n.id AND a.kind='text'
   ORDER BY a.id DESC LIMIT 1)
) candidate ORDER BY (candidate.kind='result') DESC, candidate.id DESC LIMIT 1`

// LatestWorkerOutputWithSources returns the latest result, otherwise latest
// text, with full detail for the on-demand read tool. Direct-source membership,
// task liveness and the source intent's terminal state are checked in the same
// statement as the activity read: a stale earlier node lookup cannot disclose a
// reopened source worker. Thinking and accounting rows are never candidates.
func (s *ExplorationStore) LatestWorkerOutputWithSources(intentID int64) (*Activity, error) {
	var a Activity
	a.NodeID = &intentID
	err := s.db.QueryRow(`WITH authorized_intent AS (
  SELECT n.id, n.exploration_id, 0::bigint AS source_task_id, false AS inherited
  FROM exploration_nodes n WHERE n.exploration_id=$1 AND n.id=$2 AND n.kind='intent'
  UNION ALL
  SELECT n.id, n.exploration_id, source.id AS source_task_id, true AS inherited
  FROM tasks owner
  JOIN task_relations relation ON relation.task_id=owner.id
  JOIN tasks source ON source.id=relation.source_task_id AND source.deleted_at IS NULL
  JOIN exploration_nodes n ON n.exploration_id=source.exploration_id
  WHERE owner.exploration_id=$1 AND owner.deleted_at IS NULL AND n.id=$2
    AND n.kind='intent' AND n.state IN ('done','blocked','exhausted','stopped')
)
SELECT output.id, output.kind, output.is_error, COALESCE(output.summary,''),
       COALESCE(output.detail,''), n.source_task_id, n.inherited
FROM authorized_intent n JOIN LATERAL (`+latestWorkerOutputQuery+`) output ON true`, s.expID, intentID).
		Scan(&a.ID, &a.Kind, &a.IsError, &a.Summary, &a.Detail, &a.SourceTaskID, &a.Inherited)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// WorkerFeedback is a factual, bounded view of one recent terminal intent.
// Counts describe only SampledActivityCount recent rows, never its full history.
// It is not a success/dead-end judgment and does not synthesize exploration facts.
type WorkerFeedback struct {
	IntentID               int64                 `json:"intent_id"`
	State                  string                `json:"state"`
	LastActivityID         int64                 `json:"last_activity_id"`
	LatestOutput           *WorkerFeedbackOutput `json:"latest_output,omitempty"`
	SampledActivityCount   int                   `json:"sampled_activity_count"`
	EarlierActivityOmitted bool                  `json:"earlier_activity_omitted"`
	SampledToolResults     int                   `json:"sampled_tool_results"`
	SampledToolErrors      int                   `json:"sampled_tool_errors"`
	Tools                  []WorkerFeedbackTool  `json:"tools"`
	ToolNamesOmitted       int                   `json:"tool_names_omitted,omitempty"`
	RecentErrors           []WorkerFeedbackError `json:"recent_errors"`
}

type WorkerFeedbackOutput struct {
	StepID    int64  `json:"step_id"`
	Excerpt   string `json:"excerpt"`
	IsError   bool   `json:"is_error"`
	Truncated bool   `json:"truncated"`
}

type WorkerFeedbackTool struct {
	Name          string `json:"name"`
	NameTruncated bool   `json:"name_truncated,omitempty"`
	Results       int    `json:"results"`
	Errors        int    `json:"errors"`
}

type WorkerFeedbackError struct {
	StepID        int64  `json:"step_id"`
	Tool          string `json:"tool"`
	ToolTruncated bool   `json:"tool_truncated,omitempty"`
	Excerpt       string `json:"excerpt"`
	Truncated     bool   `json:"truncated"`
}

type workerFeedbackStep struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Tool    string `json:"tool"`
	ToolKey string `json:"tool_key"`
	IsError bool   `json:"is_error"`
	Excerpt string `json:"excerpt"`
}

// RecentWorkerFeedback reads a small newest-intent window in one query. Each
// intent contributes at most 129 recent activity rows, plus two indexed output
// lookups. Detail is clipped in SQL; thinking/usage content and tool arguments
// never enter this view. A worker completing an older intent remains available
// through its completion trigger and the on-demand tools.
func (s *ExplorationStore) RecentWorkerFeedback(limit int) ([]WorkerFeedback, error) {
	if limit <= 0 || limit > workerFeedbackIntentLimit {
		limit = workerFeedbackIntentLimit
	}
	rows, err := s.db.Query(`WITH recent AS (
  SELECT id, exploration_id, state FROM exploration_nodes
  WHERE exploration_id=$1 AND kind='intent' AND state IN ('done','blocked','exhausted')
  ORDER BY id DESC LIMIT $2
)
SELECT n.id, n.state, COALESCE(output.id,0), COALESCE(output.is_error,false),
       left(COALESCE(NULLIF(output.detail,''),output.summary,''),$4),
       COALESCE(tail.steps,'[]'::jsonb)
FROM recent n
LEFT JOIN LATERAL (`+latestWorkerOutputQuery+`) output ON true
LEFT JOIN LATERAL (
  SELECT jsonb_agg(jsonb_build_object('id',a.id,'kind',a.kind,'tool',a.tool,'tool_key',a.tool_key,
         'is_error',a.is_error,'excerpt',a.excerpt) ORDER BY a.id DESC) AS steps
  FROM (
    SELECT id, COALESCE(kind,'') AS kind, is_error,
           CASE WHEN kind='tool_result' THEN left(COALESCE(tool,''),$6) ELSE '' END AS tool,
           CASE WHEN kind='tool_result' THEN md5(COALESCE(tool,'')) ELSE '' END AS tool_key,
           CASE WHEN kind='tool_result' AND is_error
                THEN left(COALESCE(NULLIF(detail,''),summary,''),$5) ELSE '' END AS excerpt
    FROM activity WHERE exploration_id=n.exploration_id AND node_id=n.id
    ORDER BY id DESC LIMIT $3
  ) a
) tail ON true
ORDER BY n.id DESC`, s.expID, limit, workerFeedbackActivityLimit+1,
		workerFeedbackOutputRunes+1, workerFeedbackErrorRunes+1, workerFeedbackToolRunes+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]WorkerFeedback, 0, limit)
	for rows.Next() {
		var f WorkerFeedback
		var outputID int64
		var outputError bool
		var excerpt string
		var raw []byte
		if err := rows.Scan(&f.IntentID, &f.State, &outputID, &outputError, &excerpt, &raw); err != nil {
			return nil, err
		}
		if outputID > 0 {
			text, truncated := workerFeedbackClip(excerpt, workerFeedbackOutputRunes)
			f.LatestOutput = &WorkerFeedbackOutput{StepID: outputID, Excerpt: text, IsError: outputError, Truncated: truncated}
		}
		var steps []workerFeedbackStep
		if err := json.Unmarshal(raw, &steps); err != nil {
			return nil, err
		}
		if len(steps) > 0 {
			f.LastActivityID = steps[0].ID
		}
		f.EarlierActivityOmitted = len(steps) > workerFeedbackActivityLimit
		if f.EarlierActivityOmitted {
			steps = steps[:workerFeedbackActivityLimit]
		}
		f.SampledActivityCount = len(steps)
		f.Tools = []WorkerFeedbackTool{}
		f.RecentErrors = []WorkerFeedbackError{}
		toolIndices := map[string]int{}
		for _, step := range steps {
			if step.Kind != "tool_result" {
				continue
			}
			f.SampledToolResults++
			name, nameTruncated := workerFeedbackClip(step.Tool, workerFeedbackToolRunes)
			// A clipped display name must not merge distinct long tool names.
			idx, exists := toolIndices[step.ToolKey]
			if !exists {
				idx = len(f.Tools)
				toolIndices[step.ToolKey] = idx
				f.Tools = append(f.Tools, WorkerFeedbackTool{Name: name, NameTruncated: nameTruncated})
			}
			f.Tools[idx].Results++
			if !step.IsError {
				continue
			}
			f.SampledToolErrors++
			f.Tools[idx].Errors++
			if len(f.RecentErrors) < workerFeedbackErrorLimit {
				text, truncated := workerFeedbackClip(step.Excerpt, workerFeedbackErrorRunes)
				f.RecentErrors = append(f.RecentErrors, WorkerFeedbackError{
					StepID: step.ID, Tool: name, ToolTruncated: nameTruncated, Excerpt: text, Truncated: truncated,
				})
			}
		}
		if len(f.Tools) > workerFeedbackToolLimit {
			f.ToolNamesOmitted = len(f.Tools) - workerFeedbackToolLimit
			f.Tools = f.Tools[:workerFeedbackToolLimit]
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func workerFeedbackClip(s string, limit int) (string, bool) {
	if utf8.RuneCountInString(s) <= limit {
		return s, false
	}
	return string([]rune(s)[:limit]), true
}
