package db

import "testing"

func TestCountFactOnlyTerminalIntents(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()

	newStore := func() *ExplorationStore {
		t.Helper()
		id, err := d.CreateExploration("fact-only diagnostics", "local test fixture")
		if err != nil {
			t.Fatal(err)
		}
		return d.Exploration(id)
	}
	// Register cleanup in defer order so the connection is still open.
	s := newStore()
	defer d.Exec("DELETE FROM explorations WHERE id=$1", s.expID)
	other := newStore()
	defer d.Exec("DELETE FROM explorations WHERE id=$1", other.expID)

	add := func(store *ExplorationStore, state string, facts int, finding bool) {
		t.Helper()
		intent, err := store.AddIntent(map[string]any{"summary": "diagnostic fixture"}, 1, nil, "test")
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < facts; j++ {
			id, err := store.AddNode("fact", map[string]any{"summary": "observed condition"}, 1, "confirmed", "test", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Link(intent, "yields", id); err != nil {
				t.Fatal(err)
			}
		}
		if finding {
			id, err := store.AddNode("finding", map[string]any{"summary": "reviewed finding"}, 1, "confirmed", "test", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Link(intent, "yields", id); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetIntentState(intent, state); err != nil {
			t.Fatal(err)
		}
	}

	for _, state := range []string{"done", "blocked", "exhausted", "stopped"} {
		add(s, state, 2, false)
	}
	add(s, "done", 1, true)
	add(s, "done", 0, false)
	add(s, "done", 0, true)
	add(s, "open", 1, false)
	add(s, "running", 1, false)
	add(other, "done", 1, false)

	if got, err := s.CountFactOnlyTerminalIntents(); err != nil || got != 4 {
		t.Fatalf("local fact-only terminal intents = %d, %v; want 4", got, err)
	}
	if got, err := other.CountFactOnlyTerminalIntents(); err != nil || got != 1 {
		t.Fatalf("other exploration fact-only terminal intents = %d, %v; want 1", got, err)
	}
}
