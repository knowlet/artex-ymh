package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A slow INSERT obtains its sequence ID before its trigger finishes. It must
// commit before a later activity in this exploration becomes visible, otherwise
// polling/SSE can advance a cursor past a row that does not exist yet. Exercise
// all three production writers, including the two graph/audit transactions.
func TestActivityCursorPreservesCommitOrder(t *testing.T) {
	for _, writer := range []string{"append", "follow_up", "cancel_rollup"} {
		t.Run(writer, func(t *testing.T) {
			d := openDisposableSchemaDB(t)
			task, err := d.CreateTask("activity commit order", "fixture", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			store := d.Exploration(task.ExplorationID)
			otherID, err := d.CreateExploration("other activity task", "fixture")
			if err != nil {
				t.Fatal(err)
			}
			other := d.Exploration(otherID)
			var first func() error
			switch writer {
			case "append":
				first = func() error {
					_, err := store.AppendActivity(Activity{Worker: "slow", Kind: "text"})
					return err
				}
			case "follow_up":
				nodeID, err := store.AddNode(KindFinding, map[string]any{"summary": "fixture"}, 1, "confirmed", "fixture", nil)
				if err != nil {
					t.Fatal(err)
				}
				findingID, err := d.AddFinding(task.ID, nodeID, "fixture", "", "low", "fixture", "evidence", "fixture", nil)
				if err != nil {
					t.Fatal(err)
				}
				first = func() error {
					_, _, err := store.AddFindingFollowUpIntent(findingID, nodeID, "follow-up fixture", Activity{Worker: "slow", Kind: "text"})
					return err
				}
			case "cancel_rollup":
				intentID, err := store.AddIntent(map[string]any{"summary": "cancel fixture"}, 1, nil, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				tokens := 10
				if _, err := store.AppendActivity(Activity{NodeID: &intentID, Worker: "worker", Kind: "result", InputTokens: &tokens}); err != nil {
					t.Fatal(err)
				}
				first = func() error { _, err := store.CancelIntent(intentID); return err }
			}

			// Hold a separate test-only gate. A trigger delays only the first writer,
			// after its ID has been allocated. Observe pg_locks so the race is
			// synchronized by a real database wait, not scheduling luck.
			const gate = int64(7337741901)
			hold, err := d.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback()
			if _, err := hold.Exec(`SELECT pg_advisory_xact_lock($1)`, gate); err != nil {
				t.Fatal(err)
			}
			if _, err := d.Exec(fmt.Sprintf(`
CREATE FUNCTION delay_activity_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.exploration_id = %d AND NEW.worker IN ('slow','token-ledger') THEN
    PERFORM pg_advisory_xact_lock(%d);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delay_activity_fixture BEFORE INSERT ON activity
FOR EACH ROW EXECUTE FUNCTION delay_activity_fixture();`, task.ExplorationID, gate)); err != nil {
				t.Fatal(err)
			}
			firstDone := make(chan error, 1)
			go func() { firstDone <- first() }()
			deadline := time.Now().Add(5 * time.Second)
			for {
				var waiting bool
				if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks
WHERE locktype='advisory' AND classid=$1 AND objid=$2 AND objsubid=1 AND NOT granted)`,
					gate>>32, gate&0xffffffff).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-firstDone:
					t.Fatalf("first writer completed before trigger gate: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("first writer did not reach trigger gate")
				}
				time.Sleep(10 * time.Millisecond)
			}

			secondDone := make(chan error, 1)
			go func() {
				_, err := store.AppendActivity(Activity{Worker: "fast", Kind: "text"})
				secondDone <- err
			}()
			// The serialization is per exploration, not a global activity lock.
			otherDone := make(chan error, 1)
			go func() {
				_, err := other.AppendActivity(Activity{Worker: "unrelated", Kind: "text"})
				otherDone <- err
			}()
			select {
			case err := <-otherDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("activity in another exploration was blocked")
			}
			select {
			case err := <-secondDone:
				_ = hold.Rollback()
				<-firstDone
				t.Fatalf("later activity committed past an invisible lower ID: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			if err := hold.Rollback(); err != nil {
				t.Fatal(err)
			}
			for _, done := range []<-chan error{firstDone, secondDone} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("activity writer did not finish after the gate opened")
				}
			}
			rows, _, err := store.ActivityList(nil, 0, 100)
			if err != nil || len(rows) != 2 || rows[0].Worker == "fast" || rows[1].Worker != "fast" {
				t.Fatalf("committed activity prefix = %+v, err=%v", rows, err)
			}
		})
	}
}

func TestActivityFollowUpUsesTaskBeforeFindingLock(t *testing.T) {
	d := openDisposableSchemaDB(t)
	task, err := d.CreateTask("follow-up lock ordering", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := d.Exploration(task.ExplorationID)
	nodeID, err := store.AddNode(KindFinding, map[string]any{"summary": "fixture"}, 1, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := d.AddFinding(task.ID, nodeID, "fixture", "", "low", "fixture", "evidence", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}

	followDB, followPID := openTaskDeleteTestDB(t, os.Getenv("ARTEX_AUTH_TEST_DSN"))
	var schema string
	if err := d.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := followDB.Exec(`SET search_path TO ` + pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	evidenceTx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer evidenceTx.Rollback()
	if err := LockTaskEvidenceTx(evidenceTx, task.ID); err != nil {
		t.Fatal(err)
	}
	followDone := make(chan error, 1)
	go func() {
		_, _, err := followDB.Exploration(task.ExplorationID).AddFindingFollowUpIntent(
			findingID, nodeID, "follow up", Activity{Worker: "system", Kind: "text"})
		followDone <- err
	}()
	// The old joined FOR SHARE locked the finding before waiting on the task.
	// Wait for that actual database wait, then complete the task-first evidence
	// mutation. It must not deadlock with a follow-up retaining the finding lock.
	if err := waitForTaskDeleteBlock(d, followPID, followDone); err != nil {
		t.Fatal(err)
	}
	if err := LockFindingEvidenceTx(evidenceTx, findingID, nil); err != nil {
		t.Fatalf("task-first evidence writer deadlocked with follow-up: %v", err)
	}
	if err := bumpEvidenceVersionTx(evidenceTx, findingID); err != nil {
		t.Fatal(err)
	}
	if err := evidenceTx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-followDone:
		if err != nil {
			t.Fatalf("follow-up failed during concurrent evidence mutation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("follow-up did not finish after evidence mutation committed")
	}
}
