package server

import (
	"context"
	"errors"
	"iter"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/llm"
)

func TestPlannerTransientRetrySchedule(t *testing.T) {
	now := time.Now()
	var schedule plannerRetrySchedule
	for _, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		if got := schedule.record(now, errors.New("openai: status 504: <html>nginx</html>")); got != want {
			t.Fatalf("delay=%v, want %v", got, want)
		}
		// Repeated notifications select the remaining cooldown, not zero and not
		// a fresh full heartbeat or full backoff.
		if got := schedule.nextDelay(now.Add(time.Second), 10*time.Minute); got != want-time.Second {
			t.Fatalf("edge changed cooldown: %v", got)
		}
		if schedule.remaining(now.Add(want)) != 0 {
			t.Fatal("retry should be due at the scheduled time")
		}
		now = now.Add(want)
	}
	for _, err := range []error{nil, context.Canceled, errors.New("status 401"), errors.New("ContextWindowExceededError"), agent.ErrPlannerNoProgress} {
		schedule.record(now, errors.New("unexpected EOF"))
		if schedule.record(now, err) != 0 || schedule.nextDelay(now, 10*time.Minute) != 10*time.Minute {
			t.Fatalf("non-transient error/success did not restore heartbeat: %v", err)
		}
	}
}

type plannerOutageProvider struct{ calls atomic.Int32 }

func (p *plannerOutageProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.calls.Add(1)
		yield(llm.StreamEvent{}, errors.New("openai: status 504: gateway timeout"))
	}
}

func (p *plannerOutageProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return accumulateStreamForTest(ctx, p.Stream, req)
}

func TestPlannerOutageNotificationsRespectCooldown(t *testing.T) {
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("disposable PostgreSQL not configured")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("planner outage fixture", "inspect fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{})
	if _, err := task.Store.AddGoal(map[string]any{"text": "fixture goal"}, "human"); err != nil {
		t.Fatal(err)
	}
	p := &plannerOutageProvider{}
	planner := agent.NewPlanner(p, "fixture", t.TempDir(), nil, 32_000, 1)
	e := NewEngine(m)
	e.debounce = time.Millisecond
	e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return planner, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.plannerLoop(ctx, task) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("planner did not stop on cancellation")
		}
	}()
	task.Notify()
	deadline := time.Now().Add(5 * time.Second)
	for p.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.calls.Load() != 1 {
		t.Fatal("planner never attempted the fixture request")
	}
	// Give the round time to persist its error, then mimic a burst of workers
	// finishing. The actual loop must not issue another model call in cooldown.
	for range 20 {
		task.Notify()
		time.Sleep(5 * time.Millisecond)
	}
	if got := p.calls.Load(); got != 1 {
		t.Fatalf("notifications bypassed the outage cooldown: calls=%d", got)
	}
}
