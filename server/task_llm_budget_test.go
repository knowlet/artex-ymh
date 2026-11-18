package server

import (
	"context"
	"errors"
	"iter"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type slowRetryModel struct {
	deadlines []time.Time
}

func (p *slowRetryModel) wait(ctx context.Context) error {
	d, _ := ctx.Deadline()
	p.deadlines = append(p.deadlines, d)
	timer := time.NewTimer(650 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("openai: status 504: gateway timeout")
	}
}

func (p *slowRetryModel) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) { yield(llm.StreamEvent{}, p.wait(ctx)) }
}

func (p *slowRetryModel) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, p.wait(ctx)
}

type chainExhaustedAfterCallDeadline struct{}

func (chainExhaustedAfterCallDeadline) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("insufficient_quota"))
	}
}

func (chainExhaustedAfterCallDeadline) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	timer := time.NewTimer(80 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	return llm.Message{}, "", llm.Usage{}, errors.New("insufficient_quota")
}

// Router returned a terminal quota outcome while the call timeout context had already
// expired; WithCallTimeout must not replace that typed result with CallTimeoutError.
func TestTaskLLMChainExhaustedSurvivesCallTimeout(t *testing.T) {
	t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "1")
	hooks := taskLLMStreamHooks{
		current: func() (taskLLMSelection, error) {
			return taskLLMSelection{profileID: 1, provider: chainExhaustedAfterCallDeadline{}}, nil
		},
		exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
			return db.TaskLLMTransition{Advanced: true, ChainExhausted: true}, nil
		},
	}
	provider := agent.WithCallTimeout(taskLLMCall{taskID: "fixture", hooks: hooks}, "task", "worker")
	_, _, _, err := provider.Complete(context.Background(), llm.CompletionRequest{})
	if !isTaskLLMChainExhausted(err) {
		t.Fatalf("chain exhausted outcome must survive call timeout wrapper: %T %v", err, err)
	}
	var timeout *agent.CallTimeoutError
	if errors.As(err, &timeout) {
		t.Fatalf("quota exhaustion must not be misclassified as transient timeout: %v", err)
	}
}

func TestTaskLLMRetrySharesCallBudget(t *testing.T) {
	t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "1")
	for _, stream := range []bool{false, true} {
		p := &slowRetryModel{}
		hooks := taskLLMStreamHooks{current: func() (taskLLMSelection, error) {
			return taskLLMSelection{provider: p, retry: agent.RetryConfig{StreamInterval: time.Millisecond}}, nil
		}}
		provider := agent.WithCallTimeout(taskLLMCall{taskID: "fixture", hooks: hooks}, "task", "planner")
		start := time.Now()
		var err error
		if stream {
			_, err = collectTaskLLMStream(provider.Stream(context.Background(), llm.CompletionRequest{}))
		} else {
			_, _, _, err = provider.Complete(context.Background(), llm.CompletionRequest{})
		}
		var timeout *agent.CallTimeoutError
		if !errors.As(err, &timeout) || len(p.deadlines) != 2 {
			t.Fatalf("stream=%v: calls=%d error=%v", stream, len(p.deadlines), err)
		}
		if p.deadlines[0] != p.deadlines[1] || time.Since(start) > 1700*time.Millisecond {
			t.Fatalf("stream=%v: retry renewed the budget: deadlines=%v elapsed=%v", stream, p.deadlines, time.Since(start))
		}
	}
}
