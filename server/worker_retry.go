package server

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// The SDK can execute a streaming tool before committing that turn to the
// transcript. Compare the observed tool executions with durable history before
// retrying, rather than assuming Resume alone prevents repeated side effects.
type workerRetryTrace struct {
	mu            sync.Mutex
	pending       map[string]int
	completed     []string
	checkpoint    agent.WorkerRetryCheckpoint
	checkpointErr error
}

func (t *workerRetryTrace) record(a db.Activity) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch a.Kind {
	case "tool_use":
		if t.pending == nil {
			t.pending = map[string]int{}
		}
		t.pending[a.ToolUseID]++
	case "tool_result":
		if t.pending[a.ToolUseID] > 1 {
			t.pending[a.ToolUseID]--
		} else {
			delete(t.pending, a.ToolUseID)
		}
		t.completed = append(t.completed, a.ToolUseID)
	}
}

func (t *workerRetryTrace) check(worker *agent.Worker, explorationID, intentID int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pending) > 0 {
		return fmt.Errorf("worker model recovery has unfinished tool executions")
	}
	if t.checkpointErr != nil {
		return t.checkpointErr
	}
	return worker.CheckModelRetryTranscriptSince(explorationID, intentID, t.checkpoint, t.completed)
}

// deferWorkerModelRetry returns true once a recoverable intent is parked. No
// NotifyDone is sent: it is still active and must not finalize the task or appear
// as an exhausted exploration direction to the planner.
func (e *Engine) deferWorkerModelRetry(t *Task, name string, worker *agent.Worker, intent *db.Node, trace *workerRetryTrace, modelErr error) bool {
	retries, interval := e.modelErrorRetryPolicy()
	stop := "disabled"
	if retries > 0 {
		if err := trace.check(worker, t.Store.ID(), intent.ID); err != nil {
			stop = "transcript_unavailable"
			log.Printf("[worker %s] task %s intent #%d recovery refused: %v", name, t.ID, intent.ID, err)
		} else {
			var deadline time.Time
			if unix := e.taskDeadline(t); unix > 0 {
				deadline = time.Unix(unix, 0)
			}
			decision, err := t.Store.ScheduleIntentModelRetry(intent.ID, retries, interval, deadline)
			if err != nil {
				stop = "schedule_failed"
				log.Printf("[worker %s] task %s intent #%d recovery persistence failed: %v", name, t.ID, intent.ID, err)
			} else if decision.Scheduled {
				metadata, _ := json.Marshal(map[string]any{"model_retry": map[string]any{
					"status": "scheduled", "attempt": decision.Attempt, "max_retries": retries,
					"retry_at": decision.RetryAt, "resume_session": agent.WorkerSessionID(t.Store.ID(), intent.ID),
				}})
				iid := intent.ID
				e.emitActivity(t, db.Activity{NodeID: &iid, Worker: name, Kind: "system", Metadata: metadata,
					Summary: fmt.Sprintf("模型暂时不可用：意图将在 %s 从原会话恢复 (%d/%d)", decision.RetryAt.UTC().Format(time.RFC3339), decision.Attempt, retries),
					Detail:  fmt.Sprintf("已保留事实和工具结果；冷却期间释放 worker。错误：%s", preview(modelErr.Error(), 500)),
				})
				log.Printf("[worker %s] task %s intent #%d model recovery scheduled at %s (%d/%d)", name, t.ID, intent.ID, decision.RetryAt.UTC().Format(time.RFC3339), decision.Attempt, retries)
				e.touch(t.ID)
				return true
			} else {
				stop = decision.Stop
			}
		}
	}
	iid := intent.ID
	metadata, _ := json.Marshal(map[string]any{"model_retry": map[string]any{"status": "stopped", "reason": stop}})
	e.emitActivity(t, db.Activity{NodeID: &iid, Worker: name, Kind: "system", Metadata: metadata,
		Summary: "模型故障自动恢复停止：" + stop,
		Detail:  "这不是目标不可利用的证据。请检查模型配置、会话与执行记录；处理根因后可人工重跑该意图。",
	})
	return false
}
