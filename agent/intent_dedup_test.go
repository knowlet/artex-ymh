package agent

import (
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestAddIntentConcurrentDuplicates(t *testing.T) {
	_, ts, _ := plannerProgressStore(t, 0)
	tools := NewToolSet(ts, "planner")
	const count = 12
	var wg sync.WaitGroup
	ids := make(chan int64, count)
	for range count {
		wg.Go(func() {
			id, err := tools.addOneIntent(intentItem{Summary: "same fixture work"})
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
	for id := range ids {
		unique[id] = true
	}
	if len(unique) != 1 {
		t.Fatalf("identical concurrent requests created %d independently claimable intents", len(unique))
	}
	nodes, err := ts.ListByKind(db.KindIntent, 100)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes=%d err=%v", len(nodes), err)
	}
}
