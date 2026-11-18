package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
)

const (
	plannerRecoveryTurns   = 8
	plannerRecoveryTimeout = 90 * time.Second
	plannerStallThreshold  = 3
)

// ErrPlannerNoProgress distinguishes an idle planning round from successful
// planning. The engine logs this failure while the normal heartbeat remains in
// control; this check never wakes itself or invents an intent.
var ErrPlannerNoProgress = errors.New("planner made no committed intent or goal progress")

func plannerDeadlineExpired(clock TaskClock) bool {
	return clock.DeadlineUnix > 0 && !time.Now().Before(time.Unix(clock.DeadlineUnix, 0))
}

// plannerBeforeProgress snapshots committed graph state before a planning round.
// A failed read is best-effort: callers get a zero snapshot and beforeOK=false so
// stall detection does not treat missing data as real progress or an idle episode.
func plannerBeforeProgress(ctx context.Context, ts *db.ExplorationStore, clock TaskClock) (before db.PlannerProgress, beforeOK bool) {
	if clock.Final || plannerDeadlineExpired(clock) {
		return before, true
	}
	before, err := ts.PlannerProgress(ctx)
	if err != nil {
		log.Printf("[planner] read progress before round (best-effort): %v", err)
		return db.PlannerProgress{}, false
	}
	return before, true
}

// recoveryBudget is a separate, bounded correction within the same planning
// round. It never renews the task deadline or expands a positive turn limit.
func recoveryBudget(maxTurns int, clock TaskClock, now time.Time) (int, time.Duration, bool) {
	if clock.Final {
		return 0, 0, false
	}
	turns, duration := plannerRecoveryTurns, plannerRecoveryTimeout
	if maxTurns > 0 && maxTurns < turns {
		turns = maxTurns
	}
	if clock.DeadlineUnix > 0 {
		remaining := time.Unix(clock.DeadlineUnix, 0).Sub(now)
		if remaining <= 0 {
			return 0, 0, false
		}
		if remaining < duration {
			duration = remaining
		}
	}
	return turns, duration, true
}

func (p *Planner) runWithProgressCheck(ctx context.Context, opts agentcore.Options, input, recoveryGuidance string, ts *db.ExplorationStore, before db.PlannerProgress, beforeOK bool, heartbeat bool, overview func() map[string]any, goalMet func() bool, emit func(db.Activity)) error {
	// An explicitly enabled goal_met tool completes the task through ToolSet's
	// authoritative flag without rewriting individual goal nodes. Preserve that
	// existing contract; assistant prose alone never sets this flag.
	completed := func() bool { return goalMet != nil && goalMet() }
	var exchanges plannerExchangeDigest
	record := func(a db.Activity) {
		exchanges.record(a)
		if emit != nil {
			emit(a)
		}
	}
	conclusion, terminal, runErr := captureRun(ctx, opts, input, record)
	clock := taskClockFrom(ctx)
	if clock.Final || ctx.Err() != nil || plannerDeadlineExpired(clock) {
		return runErr // final settlement/pause/kill must not create work or warnings
	}
	after, err := ts.PlannerProgress(ctx)
	if err != nil {
		return errors.Join(runErr, fmt.Errorf("read planner progress after round: %w", err))
	}
	required := heartbeat && before.NeedsWork()
	stalled := required && beforeOK && !completed() && after.NeedsWork() && !after.AdvancedFrom(before)
	turns, duration, canRecover := recoveryBudget(opts.MaxTurns, clock, time.Now())
	// A provider/DSML error is already actionable. Do not blindly retry it or
	// override a hook stop. Only a normally completed/budget-limited planning
	// response is eligible for the corrective instruction.
	if stalled && runErr == nil && canRecover && (terminal == harness.ReasonCompleted || terminal == harness.ReasonMaxTurns) {
		retryOpts := opts
		retryOpts.MaxTurns, retryOpts.MaxDuration = turns, duration
		retryOpts.Settlement = nil // recovery cannot spawn another wrap-up/retry loop
		retryInput := plannerAdaptiveRecoveryPrompt + fmt.Sprintf("\n本次最多 %d 个模型回合、%s（受任务剩余时间进一步限制）；选择与提交都使用现有工具与审批。", turns, duration.Round(time.Millisecond))
		retryInput += recoveryGuidance // derived from the final permitted tools, never an unlock
		retryInput += renderGraphOverview(overview()) + renderPlannerTodos(opts.Todos.List())
		retryInput += exchanges.render()
		if conclusion != "" {
			retryInput += "\n\n上一阶段结论：\n" + WrapUntrustedData("planner-output", truncOutput(conclusion, 2000))
		}
		// Refresh again after building the potentially expensive overview. This
		// narrows the worker/main-agent race without holding a lock across an LLM
		// call; the instruction above also handles a later visible graph change.
		after, err = ts.PlannerProgress(ctx)
		if err != nil {
			return errors.Join(runErr, fmt.Errorf("recheck planner progress before correction: %w", err))
		}
		stalled = beforeOK && !completed() && after.NeedsWork() && !after.AdvancedFrom(before)
		_, duration, canRecover = recoveryBudget(opts.MaxTurns, clock, time.Now())
		if stalled && canRecover {
			// Recompute remaining time: overview reads must not extend the task
			// deadline captured by the first budget calculation.
			retryOpts.MaxDuration = duration
			record(db.Activity{Kind: "text", Summary: "规划进度校验：未产生实际意图或目标进展，本轮追加一次有界重新规划",
				Metadata: json.RawMessage(`{"kind":"planner_progress_retry"}`)})
			retryCtx, cancel := context.WithTimeout(ctx, duration)
			_, terminal, runErr = captureRun(retryCtx, retryOpts, retryInput, record)
			cancel()
		}
		if ctx.Err() != nil {
			return runErr
		}
		after, err = ts.PlannerProgress(ctx)
		if err != nil {
			return errors.Join(runErr, fmt.Errorf("read planner progress after correction: %w", err))
		}
		stalled = beforeOK && !completed() && after.NeedsWork() && !after.AdvancedFrom(before)
	}
	if plannerDeadlineExpired(clock) {
		return runErr // task coordinator owns deadline settlement, not this monitor
	}
	if !required && !completed() && after.NeedsWork() && beforeOK && !after.AdvancedFrom(before) {
		return runErr // event-triggered no-op rounds do not count as idle heartbeats
	}
	report, err := ts.FinishPlannerProgress(ctx, before, stalled, plannerStallThreshold, opts.MaxTurns, string(terminal))
	if err != nil {
		return errors.Join(runErr, fmt.Errorf("record planner progress: %w", err))
	}
	if report.ConsecutiveStalls == 0 {
		return runErr
	}
	detail := fmt.Sprintf("未达成目标且没有 open/running 意图；连续至少 %d 轮心跳未产生实际进展。检查最后的工具结果、模型工具调用格式和 agents.max_turns。", report.ConsecutiveStalls)
	if report.HintID > 0 {
		detail += fmt.Sprintf(" 已建立人工介入提示 #%d。", report.HintID)
	}
	metadata, _ := json.Marshal(map[string]any{"kind": "planner_stalled", "consecutive_stalls": report.ConsecutiveStalls, "hint_id": report.HintID, "terminal_reason": string(terminal)})
	record(db.Activity{Kind: "text", IsError: true, Summary: detail, Detail: detail, Metadata: metadata})
	return errors.Join(runErr, ErrPlannerNoProgress)
}
