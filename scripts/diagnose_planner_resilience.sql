-- PostgreSQL 16+; read-only. Defaults to task 2 and the last 24 hours.
-- psql "$ARTEX_PG_DSN" -X -v ON_ERROR_STOP=1 -v task_id=2 \
--   -v since_hours=24 -f scripts/diagnose_planner_resilience.sql
-- Run against the deployment only when operational access is authorized.
\set ON_ERROR_STOP on
\pset pager off
\if :{?task_id}
\else
\set task_id 2
\endif
\if :{?since_hours}
\else
\set since_hours 24
\endif

BEGIN READ ONLY;
SET LOCAL statement_timeout = '15s';

SELECT id AS task_id, exploration_id, status, paused, plan_heartbeat_seconds,
       created_at, deadline_at
FROM tasks
WHERE id = :'task_id'::bigint;

-- done says execution ended. Findings and proven goals are counted separately.
SELECT n.kind, n.state, count(*) AS node_count
FROM exploration_nodes n
JOIN tasks t ON t.exploration_id = n.exploration_id
WHERE t.id = :'task_id'::bigint
GROUP BY n.kind, n.state
ORDER BY n.kind, n.state;

-- Chronological timestamps with a stable tie-breaker, never physical ctid.
-- Read newer retry columns through to_jsonb so this also works before upgrade.
SELECT n.id, n.kind, n.state, n.owner, n.created_at, n.updated_at, n.completed_at,
       to_jsonb(n)->>'model_retry_count' AS model_retry_count,
       to_jsonb(n)->>'model_retry_at' AS model_retry_at
FROM exploration_nodes n
JOIN tasks t ON t.exploration_id = n.exploration_id
WHERE t.id = :'task_id'::bigint AND n.kind = 'intent'
ORDER BY n.created_at DESC, n.id DESC
LIMIT 30;

-- No evidence, request bodies, credentials, or session tokens are printed.
SELECT f.id, f.node_id, f.vulnclass, f.severity, f.status, f.created_at
FROM findings f
WHERE f.task_id = :'task_id'::bigint
ORDER BY f.created_at DESC, f.id DESC
LIMIT 100;

SELECT status, severity, count(*) AS finding_count
FROM findings
WHERE task_id = :'task_id'::bigint
GROUP BY status, severity
ORDER BY status, severity;

-- Count observed arguments nesting independently of successful graph writes.
-- pg_input_is_valid prevents malformed/truncated tool JSON from aborting this
-- query. JSON objects and JSON strings inside arguments are both recognized.
WITH RECURSIVE calls AS (
    SELECT a.id,
           CASE WHEN pg_input_is_valid(a.detail, 'jsonb')
                THEN a.detail::jsonb END AS args
    FROM activity a
    JOIN tasks t ON t.exploration_id = a.exploration_id
    WHERE t.id = :'task_id'::bigint AND a.kind = 'tool_use'
      AND a.tool = 'add_intent'
      AND a.created_at >= now() - make_interval(hours => :'since_hours'::int)
), walk AS (
    SELECT id, args, 0 AS depth FROM calls
    UNION ALL
    SELECT id,
           CASE jsonb_typeof(args->'arguments')
               WHEN 'object' THEN args->'arguments'
               WHEN 'string' THEN
                   CASE WHEN pg_input_is_valid(args->>'arguments', 'jsonb')
                        THEN (args->>'arguments')::jsonb END
           END,
           depth + 1
    FROM walk
    WHERE depth < 8 AND jsonb_typeof(args) = 'object' AND args ? 'arguments'
), last_layer AS (
    SELECT DISTINCT ON (id) id, args, depth
    FROM walk
    ORDER BY id, depth DESC
)
SELECT depth AS observed_wrapper_depth,
       CASE WHEN args IS NULL THEN 'invalid_json'
            WHEN jsonb_typeof(args) <> 'object' THEN 'non_object'
            WHEN args ? 'arguments' THEN 'depth_limit_or_unresolved'
            WHEN args ? 'intents' THEN 'batch'
            WHEN args ? 'summary' THEN 'single'
            ELSE 'missing_intent_fields' END AS final_shape,
       count(*) AS call_count
FROM last_layer
GROUP BY depth, final_shape
ORDER BY depth, final_shape;

SELECT CASE
           WHEN a.detail LIKE '%summary 不能为空%' THEN 'missing_summary'
           WHEN a.detail LIKE '%不能作为意图锚点%' THEN 'invalid_evidence_parent'
           WHEN a.detail LIKE '%arguments wrapper%' THEN 'invalid_arguments_wrapper'
           WHEN a.detail LIKE '%inside each intents item%' THEN 'batch_shared_fields'
           ELSE 'other_tool_error'
       END AS error_kind, count(*) AS error_count
FROM activity a
JOIN tasks t ON t.exploration_id = a.exploration_id
WHERE t.id = :'task_id'::bigint AND a.kind = 'tool_result'
  AND a.tool = 'add_intent' AND a.is_error
  AND a.created_at >= now() - make_interval(hours => :'since_hours'::int)
GROUP BY error_kind
ORDER BY error_count DESC, error_kind;

-- Batch responses can contain per-item errors even when is_error is false.
SELECT a.id, a.created_at, a.tool_use_id, a.is_error,
       CASE WHEN pg_input_is_valid(a.detail, 'jsonb')
            THEN COALESCE(jsonb_typeof((a.detail::jsonb)->'errors') = 'object'
                          AND (a.detail::jsonb)->'errors' <> '{}'::jsonb, false)
            ELSE false END AS has_batch_errors
FROM activity a
JOIN tasks t ON t.exploration_id = a.exploration_id
WHERE t.id = :'task_id'::bigint AND a.kind = 'tool_result'
  AND a.tool = 'add_intent'
  AND a.created_at >= now() - make_interval(hours => :'since_hours'::int)
ORDER BY a.created_at DESC, a.id DESC
LIMIT 30;

-- Find the actual timestamp of model_error rows; do not infer it from row order.
SELECT a.id, a.node_id, a.worker, a.created_at, a.is_error,
       a.metadata->'model_retry'->>'status' AS model_retry_status,
       a.metadata->'model_retry'->>'attempt' AS model_retry_attempt,
       a.metadata->'model_retry'->>'retry_at' AS model_retry_at
FROM activity a
JOIN tasks t ON t.exploration_id = a.exploration_id
WHERE t.id = :'task_id'::bigint
  AND (a.detail LIKE '%model_error%'
       OR a.metadata ? 'model_retry')
  AND a.created_at >= now() - make_interval(hours => :'since_hours'::int)
ORDER BY a.created_at DESC, a.id DESC
LIMIT 50;

ROLLBACK;
