package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSchedulerTaskTimeoutsFireOutOfIDOrder(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { pg.Close() })
	sc := &Scheduler{pg: pg}
	original, err := pg.GetSchedState(schedKeyFiredTimeouts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if original == "" {
			if _, err := pg.Exec("DELETE FROM scheduler_state WHERE key=$1", schedKeyFiredTimeouts); err != nil {
				t.Error(err)
			}
		} else if err := pg.SetSchedState(schedKeyFiredTimeouts, original); err != nil {
			t.Error(err)
		}
	})
	if err := pg.SetSchedState(schedKeyFiredTimeouts, ""); err != nil {
		t.Fatal(err)
	}
	createTask := func() int64 {
		t.Helper()
		task, err := pg.CreateTaskWithOptions("timeout order", "test goal", db.TaskCreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
		return task.ID
	}
	timeOut := func(id int64) {
		t.Helper()
		if _, err := pg.Exec("UPDATE tasks SET status='timeout' WHERE id=$1", id); err != nil {
			t.Fatal(err)
		}
	}
	historical := createTask()
	timeOut(historical)
	sc.initTimeoutSet()
	for _, event := range sc.newTaskTimeouts() {
		if event.TaskID == historical {
			t.Fatal("historical timeout replayed at initialization")
		}
	}
	older, newer := createTask(), createTask()
	fired := func(s *Scheduler) []int64 {
		var out []int64
		for _, event := range s.newTaskTimeouts() {
			if event.TaskID == older || event.TaskID == newer {
				out = append(out, event.TaskID)
			}
		}
		return out
	}
	timeOut(newer)
	if got := fired(sc); len(got) != 1 || got[0] != newer {
		t.Fatalf("newer timeout: fired %v, want [%d]", got, newer)
	}
	// Simulate a scheduler restart with its persisted state.
	restarted := &Scheduler{pg: pg}
	restarted.initTimeoutSet()
	timeOut(older)
	if got := fired(restarted); len(got) != 1 || got[0] != older {
		t.Fatalf("older timeout after restart: fired %v, want [%d]", got, older)
	}
	if got := fired(restarted); len(got) != 0 {
		t.Fatalf("duplicate timeout events: %v", got)
	}
}
