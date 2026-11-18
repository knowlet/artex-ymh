package db

import (
	"sync"
	"testing"
	"time"
)

func modelRetryTestStore(t *testing.T) (*DB, *ExplorationStore, int64) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	exp, err := d.CreateExploration(t.Name(), "worker recovery fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	s := d.Exploration(exp)
	id, err := s.AddIntent(map[string]any{"summary": "resume fixture"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ClaimIntent(id, "work#1"); err != nil || !ok {
		t.Fatalf("claim=%v err=%v", ok, err)
	}
	return d, s, id
}

func TestIntentModelRetryPersistsCooldownAndBudget(t *testing.T) {
	d, s, id := modelRetryTestStore(t)
	first, err := s.ScheduleIntentModelRetry(id, 2, 0, time.Time{})
	if err != nil || !first.Scheduled || first.Attempt != 1 {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	if until := time.Until(first.RetryAt); until < 55*time.Second || until > 65*time.Second {
		t.Fatalf("first cooldown=%v", until)
	}
	// A fresh store models the scheduler losing all process memory on restart.
	s = d.Exploration(s.ID())
	if _, err := s.ResetRunningIntents(); err != nil {
		t.Fatal(err)
	}
	n, err := s.GetNode(id)
	if err != nil || n.State != "open" || n.ModelRetryCount != 1 || n.ModelRetryAt == nil {
		t.Fatalf("persisted=%+v err=%v", n, err)
	}
	if frontier, err := s.ReadyFrontier(20); err != nil || len(frontier) != 0 {
		t.Fatalf("cooling frontier=%+v err=%v", frontier, err)
	}
	if ok, err := s.ClaimIntent(id, "too early"); err != nil || ok {
		t.Fatalf("early direct claim=%v err=%v", ok, err)
	}
	if frontier, err := s.Frontier(20); err != nil || len(frontier) != 1 || frontier[0].ModelRetryAt == nil {
		t.Fatalf("pending retry must remain visible: %+v %v", frontier, err)
	}
	if active, err := s.HasActiveIntent(); err != nil || !active {
		t.Fatalf("cooling intent must remain active: %v %v", active, err)
	}
	if count, err := s.CountOpenIntents(); err != nil || count != 1 {
		t.Fatalf("cooling intent missing from admission cap: %d %v", count, err)
	}
	if changed, err := s.CompareAndSetIntentState(id, "open", "paused"); err != nil || !changed {
		t.Fatalf("pause deferred work: %v %v", changed, err)
	}
	if changed, err := s.CompareAndSetIntentState(id, "paused", "open"); err != nil || !changed {
		t.Fatalf("resume deferred work: %v %v", changed, err)
	}
	if ok, err := s.ClaimIntent(id, "resume too early"); err != nil || ok {
		t.Fatalf("pause/resume discarded cooldown: %v %v", ok, err)
	}
	for attempt := 2; attempt <= 3; attempt++ {
		if _, err := d.Exec(`UPDATE exploration_nodes SET model_retry_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.ClaimIntent(id, "next worker"); err != nil || !ok {
			t.Fatalf("due claim=%v err=%v", ok, err)
		}
		decision, err := s.ScheduleIntentModelRetry(id, 2, 0, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 2 {
			if !decision.Scheduled || decision.Attempt != 2 || time.Until(decision.RetryAt) < 4*time.Minute {
				t.Fatalf("second=%+v", decision)
			}
		} else if decision.Scheduled || decision.Stop != "exhausted" {
			t.Fatalf("budget must survive claims: %+v", decision)
		}
	}
	if err := s.SetIntentState(id, "blocked"); err != nil {
		t.Fatal(err)
	}
	if decision, err := s.ScheduleIntentModelRetry(id, 20, 0, time.Time{}); err != nil || decision.Scheduled {
		t.Fatalf("never reopen terminal work: %+v %v", decision, err)
	}
	if ok, err := s.ReopenIntent(id); err != nil || !ok {
		t.Fatalf("manual rerun=%v %v", ok, err)
	}
	n, err = s.GetNode(id)
	if err != nil || n.ModelRetryCount != 0 || n.ModelRetryAt != nil {
		t.Fatalf("manual rerun must reset budget: %+v %v", n, err)
	}
}

func TestIntentModelRetryConcurrentScheduleAndClaim(t *testing.T) {
	d, s, id := modelRetryTestStore(t)
	const contenders = 12
	var wg sync.WaitGroup
	results := make(chan IntentModelRetry, contenders)
	errors := make(chan error, contenders)
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.ScheduleIntentModelRetry(id, 2, time.Minute, time.Time{})
			results <- r
			errors <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	winners := 0
	for r := range results {
		if r.Scheduled {
			winners++
		}
	}
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("schedule winners=%d", winners)
	}
	if _, err := d.Exec(`UPDATE exploration_nodes SET model_retry_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	claims := make(chan bool, contenders)
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.ClaimIntent(id, "contender")
			if err != nil {
				t.Error(err)
			}
			claims <- ok
		}()
	}
	wg.Wait()
	close(claims)
	winners = 0
	for ok := range claims {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("claim winners=%d", winners)
	}
}

func TestIntentModelRetryHonorsControlDeadlineAndDisable(t *testing.T) {
	_, s, id := modelRetryTestStore(t)
	if r, err := s.ScheduleIntentModelRetry(id, -1, 0, time.Time{}); err != nil || r.Scheduled || r.Stop != "disabled" {
		t.Fatalf("disabled=%+v %v", r, err)
	}
	if r, err := s.ScheduleIntentModelRetry(id, 2, 0, time.Now().Add(10*time.Second)); err != nil || r.Scheduled || r.Stop != "deadline" {
		t.Fatalf("deadline=%+v %v", r, err)
	}
	for _, state := range []string{"paused", "stopped", "blocked", "exhausted", "done", "deleted"} {
		if err := s.SetIntentState(id, state); err != nil {
			t.Fatal(err)
		}
		if r, err := s.ScheduleIntentModelRetry(id, 2, 0, time.Time{}); err != nil || r.Scheduled || r.Stop != "state_changed" {
			t.Fatalf("state %s was revived: %+v %v", state, r, err)
		}
	}
}

func TestIntentModelRetryDelayBounds(t *testing.T) {
	for _, c := range []struct {
		attempt  int
		interval time.Duration
		want     time.Duration
	}{{1, 0, time.Minute}, {2, 0, 5 * time.Minute}, {3, 0, 30 * time.Minute}, {20, 0, 30 * time.Minute}, {2, 3 * time.Second, 3 * time.Second}, {3, 24 * time.Hour, time.Hour}} {
		if got := ModelRetryDelay(c.attempt, c.interval); got != c.want {
			t.Fatalf("attempt=%d interval=%v got=%v want=%v", c.attempt, c.interval, got, c.want)
		}
	}
}
