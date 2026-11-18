package db

import (
	"sync"
	"testing"
	"time"
)

func TestIntentDedupConcurrentAdmission(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	exp, err := d.CreateExploration(t.Name(), "local fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	s := d.Exploration(exp)
	const count = 12
	var wg sync.WaitGroup
	ids := make(chan int64, count)
	for range count {
		wg.Go(func() {
			id, err := s.AddIntent(map[string]any{"summary": "same fixture"}, 5, nil, "planner")
			if err != nil {
				t.Error(err)
				return
			}
			ids <- id
		})
	}
	wg.Wait()
	close(ids)
	unique := map[int64]bool{}
	claims := 0
	for id := range ids {
		unique[id] = true
		ok, err := s.ClaimIntent(id, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			claims++
		}
	}
	if len(unique) != 1 || claims != 1 {
		t.Fatalf("identical admissions created %d IDs and %d independently runnable jobs", len(unique), claims)
	}
}

func TestIntentDedupPreservesIdentityAndControl(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	exp, err := d.CreateExploration(t.Name(), "local fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	s := d.Exploration(exp)
	parent, err := s.AddNode(KindFact, map[string]any{"summary": "fixture evidence"}, 0, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	otherParent, err := s.AddNode(KindFact, map[string]any{"summary": "new evidence"}, 0, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: "pr30-dedup.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, asset) })
	payload := map[string]any{"summary": "fixture work"}
	add := func(p map[string]any, anchors, parents []int64) int64 {
		t.Helper()
		id, err := s.AddIntentWithParents(p, 5, anchors, "planner", parents)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	id := add(payload, nil, []int64{parent})
	if got := add(payload, nil, []int64{parent, parent}); got != id {
		t.Fatal("parent set is order/duplicate sensitive")
	}
	for _, state := range []string{"open", "running", "paused"} {
		if err := s.SetIntentState(id, state); err != nil {
			t.Fatal(err)
		}
		if got := add(payload, nil, []int64{parent}); got != id {
			t.Fatalf("duplicate bypassed state %s", state)
		}
		n, err := s.GetNode(id)
		if err != nil || n.State != state {
			t.Fatalf("state changed: %+v %v", n, err)
		}
	}
	if err := s.SetIntentState(id, "running"); err != nil {
		t.Fatal(err)
	}
	decision, err := s.ScheduleIntentModelRetry(id, 2, time.Minute, time.Time{})
	if err != nil || !decision.Scheduled {
		t.Fatalf("schedule %+v %v", decision, err)
	}
	if got := add(payload, nil, []int64{parent}); got != id {
		t.Fatal("cooldown bypassed")
	}
	n, err := s.GetNode(id)
	if err != nil || n.ModelRetryCount != 1 || n.ModelRetryAt == nil || !n.ModelRetryAt.Equal(decision.RetryAt) {
		t.Fatalf("retry budget changed: %+v %v", n, err)
	}
	for _, distinct := range []int64{
		add(payload, nil, []int64{otherParent}),
		add(payload, []int64{asset}, []int64{parent}),
		add(map[string]any{"summary": "fixture work", "exploration": map[string]any{"question": "different evidence"}}, nil, []int64{parent}),
	} {
		if distinct == id {
			t.Fatal("distinct work was swallowed")
		}
	}
	for _, state := range []string{"done", "blocked", "exhausted", "stopped", "deleted"} {
		if err := s.SetIntentState(id, state); err != nil {
			t.Fatal(err)
		}
		next := add(payload, nil, []int64{parent})
		if next != id {
			t.Fatalf("planner replaced terminal %s work with a fresh budget", state)
		}
		id = next
	}
	otherExp, err := d.CreateExploration(t.Name(), "independent exploration")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, otherExp) })
	otherID, err := d.Exploration(otherExp).AddIntentWithParents(payload, 5, nil, "planner", []int64{parent})
	if err != nil || otherID == id {
		t.Fatalf("cross exploration identity %d %v", otherID, err)
	}
}

func TestIntentDedupLineageFailureRollsBack(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	exp, err := d.CreateExploration(t.Name(), "local fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	s := d.Exploration(exp)
	if _, err := s.AddIntentWithParents(map[string]any{"summary": "fixture"}, 5, nil, "planner", []int64{-1}); err == nil {
		t.Fatal("missing lineage accepted")
	}
	nodes, err := s.ListByKind(KindIntent, 10)
	if err != nil || len(nodes) != 0 {
		t.Fatalf("orphan persisted: %+v %v", nodes, err)
	}
}

func TestIntentDedupAllowsIndependentGraphCommit(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	exp, err := d.CreateExploration(t.Name(), "local fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// This holds a foreign-key KEY SHARE lock on explorations until commit.
	if _, err := tx.Exec(`INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin) VALUES($1,'fact','{}','confirmed','fixture')`, exp); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := d.Exploration(exp).AddIntent(map[string]any{"summary": "independent work"}, 5, nil, "planner")
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		_ = tx.Rollback()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("admission did not release after rollback")
		}
		t.Fatal("admission blocked independent graph insertion's commit")
	}
}
