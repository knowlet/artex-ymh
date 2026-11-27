package db

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func goalProofFixture(t *testing.T) (*DB, *ExplorationStore, int64, int64, int64) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("goal proof regression", "verify a finding", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	s := d.Exploration(task.ExplorationID)
	goal, err := s.AddGoal(map[string]any{"text": "verify a finding"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	node, err := s.AddNode(KindFinding, map[string]any{"summary": "proof"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := s.AddStandaloneFinding(task.ID, node, "test", "test", SeverityHigh, "proof", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(finding, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if err := s.Link(node, RelProves, goal); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeState(goal, "met"); err != nil {
		t.Fatal(err)
	}
	return d, s, goal, node, finding
}

func assertGoalProofState(t *testing.T, d *DB, s *ExplorationStore, goal int64, state string, proofs int) {
	t.Helper()
	n, err := s.GetNode(goal)
	if err != nil || n == nil || n.State != state {
		t.Fatalf("goal state: got %+v, err=%v; want %s", n, err, state)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE dst_id=$1 AND rel='proves'`, goal).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != proofs {
		t.Fatalf("proof edge count: got %d, want %d", count, proofs)
	}
}

func TestSecurityGoalProofInvalidatedByFindingTriage(t *testing.T) {
	d, s, goal, _, finding := goalProofFixture(t)
	if _, found, _, err := d.SetFindingStatusWithNotify(t.Context(), finding, FindingFalsePositive); err != nil || !found {
		t.Fatalf("triage: found=%v err=%v", found, err)
	}
	assertGoalProofState(t, d, s, goal, "open", 0)
}

func TestSecurityGoalProofInvalidatedByFindingDeletion(t *testing.T) {
	d, s, goal, _, finding := goalProofFixture(t)
	if n, err := d.DeleteFinding(finding); err != nil || n != 1 {
		t.Fatalf("delete: n=%d err=%v", n, err)
	}
	assertGoalProofState(t, d, s, goal, "open", 0)
}

func TestSecurityGoalProofKeepsOtherEvidenceAndManualGoals(t *testing.T) {
	d, s, goal, _, finding := goalProofFixture(t)
	other, err := s.AddNode(KindFact, map[string]any{"summary": "independent proof"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	manual, err := s.AddGoal(map[string]any{"text": "manual decision"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeState(manual, "met"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProveGoal(t.Context(), goal, other); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(finding, FindingIgnored); err != nil {
		t.Fatal(err)
	}
	assertGoalProofState(t, d, s, goal, "met", 1)
	assertGoalProofState(t, d, s, manual, "met", 0)
	// Re-confirming the revoked finding must not resurrect its old proof.
	if _, err := d.SetFindingStatus(finding, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	assertGoalProofState(t, d, s, goal, "met", 1)
}

func TestSecurityGoalProofRetainsOtherConfirmedFinding(t *testing.T) {
	d, s, goal, _, first := goalProofFixture(t)
	taskID, err := s.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	node, err := s.AddNode(KindFinding, map[string]any{}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.AddStandaloneFinding(taskID, node, "other", "other", SeverityHigh, "independent", "proof", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(second, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProveGoal(t.Context(), goal, node); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := d.SetFindingStatusWithNotify(t.Context(), first, FindingDuplicate); err != nil {
		t.Fatal(err)
	}
	assertGoalProofState(t, d, s, goal, "met", 1)
	if _, _, _, err := d.SetFindingStatusWithNotify(t.Context(), second, FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	assertGoalProofState(t, d, s, goal, "open", 0)
}

func TestSecurityGoalProofRepairOnOpen(t *testing.T) {
	d, s, goal, _, finding := goalProofFixture(t)
	manual, err := s.AddGoal(map[string]any{"text": "manual"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeState(manual, "met"); err != nil {
		t.Fatal(err)
	}
	legacyGoal, err := s.AddGoal(map[string]any{"text": "legacy"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := s.AddNode(KindFinding, map[string]any{}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProveGoal(t.Context(), legacyGoal, legacy); err != nil {
		t.Fatal(err)
	}
	tombstoneGoal, err := s.AddGoal(map[string]any{"text": "deleted finding"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	tombstone, err := s.AddNode(KindFinding, map[string]any{}, 0, "dismissed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Link(tombstone, RelProves, tombstoneGoal); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeState(tombstoneGoal, "met"); err != nil {
		t.Fatal(err)
	}
	// Emulate the previous version's triage write, which left its proof intact.
	if _, err := d.Exec(`UPDATE findings SET status='false_positive' WHERE id=$1`, finding); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		reopened, err := Open(testDSN(t))
		if err != nil {
			t.Fatal(err)
		}
		_ = reopened.Close()
		assertGoalProofState(t, d, s, goal, "open", 0)
		assertGoalProofState(t, d, s, manual, "met", 0)
		assertGoalProofState(t, d, s, legacyGoal, "met", 1)
		assertGoalProofState(t, d, s, tombstoneGoal, "open", 0)
	}
}

func TestSecurityGoalProofLegacyAttachmentBecomesPending(t *testing.T) {
	d, s, goal, _, _ := goalProofFixture(t)
	legacyGoal, err := s.AddGoal(map[string]any{"text": "legacy"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := s.AddNode(KindFinding, map[string]any{}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProveGoal(t.Context(), legacyGoal, legacy); err != nil {
		t.Fatal(err)
	}
	taskID, err := s.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddStandaloneFinding(taskID, legacy, "test", "test", SeverityHigh, "summary", "proof", "worker", nil); err != nil {
		t.Fatal(err)
	}
	assertGoalProofState(t, d, s, legacyGoal, "open", 0)
	assertGoalProofState(t, d, s, goal, "met", 1)
}

func TestSecurityGoalProofRepairAfterArchiveRestore(t *testing.T) {
	d, s, goal, _, finding := goalProofFixture(t)
	taskID, err := s.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPaused(taskID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE findings SET status='false_positive' WHERE id=$1`, finding); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(taskID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, taskID) })
	if job, err := d.ClaimTaskArchiveJob(t.Context()); err != nil || job == nil || job.ID != archive.ID {
		t.Fatalf("archive claim: %+v %v", job, err)
	}
	snapshot, err := d.SnapshotTaskArchive(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/goal-proof-fixture.tar.zst", "test-only", 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if job, err := d.ClaimTaskArchiveJob(t.Context()); err != nil || job == nil || job.ID != archive.ID {
		t.Fatalf("restore claim: %+v %v", job, err)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	assertGoalProofState(t, d, s, goal, "open", 0)
	if err := d.CompleteTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityGoalProofInvalidatedByRetestAndVerifier(t *testing.T) {
	for _, mode := range []string{"retest", "verifier", "bulk_delete", "intent_cleanup"} {
		t.Run(mode, func(t *testing.T) {
			d, s, goal, node, finding := goalProofFixture(t)
			switch mode {
			case "retest":
				r, conv, _, err := d.CreateFindingRetest(t.Context(), finding, "verify fix")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID) })
				if _, err := d.StartFindingRetest(t.Context(), r.ID); err != nil {
					t.Fatal(err)
				}
				if err := d.RecordFindingRetestResult(t.Context(), conv.ID, "fixed", "fixed", "patch verified"); err != nil {
					t.Fatal(err)
				}
				if err := d.FinishFindingRetest(r.ID, "completed", ""); err != nil {
					t.Fatal(err)
				}
			case "verifier":
				// Simulate a stale pre-fix pending proof; the verifier only changes
				// findings still pending and must remove this proof with its verdict.
				if _, err := d.Exec(`UPDATE findings SET status='pending' WHERE id=$1`, finding); err != nil {
					t.Fatal(err)
				}
				c, conv, _, err := d.CreateFindingCheck(t.Context(), finding, FindingCheckKindVerify)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID) })
				if _, err := d.StartFindingCheck(t.Context(), c.ID); err != nil {
					t.Fatal(err)
				}
				if err := d.RecordFindingCheckResult(t.Context(), conv.ID, "false_positive", "false positive", "control disproves report"); err != nil {
					t.Fatal(err)
				}
				if err := d.FinishFindingCheck(c.ID, "completed", ""); err != nil {
					t.Fatal(err)
				}
			case "bulk_delete":
				taskID, err := s.TaskID()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := d.DeleteFindingsByTask(taskID); err != nil {
					t.Fatal(err)
				}
				if _, err := s.ProveGoal(t.Context(), goal, node); err == nil {
					t.Fatal("deleted finding row became eligible synthetic proof")
				}
			case "intent_cleanup":
				intent, err := s.AddIntent(map[string]any{"summary": "work"}, 1, nil, "planner")
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Link(intent, RelYields, node); err != nil {
					t.Fatal(err)
				}
				if _, err := s.CancelIntent(intent); err != nil {
					t.Fatal(err)
				}
			}
			assertGoalProofState(t, d, s, goal, "open", 0)
		})
	}
}

func TestSecurityGoalProofScopeAndStatus(t *testing.T) {
	d, source, _, node, finding := goalProofFixture(t)
	sourceTask, err := source.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	child, err := d.CreateTaskWithOptions("dependent", "check proof", TaskCreateOptions{SourceTaskIDs: []int64{sourceTask}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(child.ID) })
	current := d.Exploration(child.ExplorationID)
	goal, err := current.AddGoal(map[string]any{"text": "inherited evidence"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := current.ProveGoal(t.Context(), goal, node); err != nil || !out.AllGoalsMet || out.GoalCount != 1 {
		t.Fatalf("direct source proof: %+v %v", out, err)
	}
	if _, err := source.ProveGoal(t.Context(), goal, node); err == nil {
		t.Fatal("foreign goal accepted")
	}
	unrelated, err := d.CreateExploration("unrelated", "unrelated")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, unrelated) })
	other, err := d.Exploration(unrelated).AddNode(KindFact, map[string]any{}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.ProveGoal(t.Context(), goal, other); err == nil {
		t.Fatal("unrelated evidence accepted")
	}
	for _, status := range []string{FindingPending, FindingInProgress, FindingFalsePositive, FindingFixed, FindingIgnored, FindingDuplicate, FindingResolved, FindingRiskAccepted} {
		if _, err := d.SetFindingStatus(finding, status); err != nil {
			t.Fatal(err)
		}
		if _, err := current.ProveGoal(t.Context(), goal, node); err == nil {
			t.Fatalf("%s finding accepted as proof", status)
		}
		assertGoalProofState(t, d, current, goal, "open", 0)
	}
	if _, err := d.SetFindingStatus(finding, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, err := current.ProveGoal(t.Context(), goal, node); err != nil {
		t.Fatal(err)
	}
	// Source task deletion must reopen a dependent task's goal even when the
	// caller preserves standalone findings. Proofs are graph-node identities.
	if _, err := d.DeleteTaskCascade(sourceTask, false, false); err != nil {
		t.Fatal(err)
	}
	assertGoalProofState(t, d, current, goal, "open", 0)
}

func TestSecurityGoalProofWriteFailureRollsBack(t *testing.T) {
	d, s, goal, node, _ := goalProofFixture(t)
	if _, err := d.Exec(`DELETE FROM exploration_edges WHERE dst_id=$1 AND rel='proves'`, goal); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeState(goal, "open"); err != nil {
		t.Fatal(err)
	}
	// Force failure after the proof edge INSERT. A rejected goal update must not
	// leave a durable proof or be reported as task completion.
	constraint := fmt.Sprintf("goal_proof_failure_%d", goal)
	if _, err := d.Exec(fmt.Sprintf(`ALTER TABLE exploration_nodes ADD CONSTRAINT %s CHECK(id<>%d OR state<>'met')`, constraint, goal)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`ALTER TABLE exploration_nodes DROP CONSTRAINT ` + constraint) })
	if _, err := s.ProveGoal(t.Context(), goal, node); err == nil {
		t.Fatal("failed goal update reported success")
	}
	assertGoalProofState(t, d, s, goal, "open", 0)
}

func TestSecurityGoalProofConcurrentRevocation(t *testing.T) {
	for _, action := range []string{"triage", "delete"} {
		for _, first := range []string{"prove", "revoke"} {
			t.Run(action+"/"+first+"_first", func(t *testing.T) {
				d, s, goal, node, finding := goalProofFixture(t)
				prover, proverPID := goalProofConnection(t)
				revoker, revokerPID := goalProofConnection(t)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				blocker, err := d.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback()
				if _, err := blocker.ExecContext(ctx, `SELECT id FROM exploration_nodes WHERE id=$1 FOR UPDATE`, goal); err != nil {
					t.Fatal(err)
				}
				proved, revoked := make(chan error, 1), make(chan error, 1)
				prove := func() { _, err := prover.Exploration(s.ID()).ProveGoal(ctx, goal, node); proved <- err }
				revoke := func() {
					if action == "triage" {
						_, _, _, err := revoker.SetFindingStatusWithNotify(ctx, finding, FindingFalsePositive)
						revoked <- err
					} else {
						_, err := revoker.DeleteFinding(finding)
						revoked <- err
					}
				}
				if first == "prove" {
					go prove()
					waitGoalProofLock(t, d, proverPID, proved)
					go revoke()
					waitGoalProofLock(t, d, revokerPID, revoked)
				} else {
					go revoke()
					waitGoalProofLock(t, d, revokerPID, revoked)
					go prove()
					waitGoalProofLock(t, d, proverPID, proved)
				}
				if err := blocker.Commit(); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-proved:
					if (err == nil) != (first == "prove") {
						t.Fatalf("proof outcome: %v, order=%s", err, first)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				select {
				case err := <-revoked:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				assertGoalProofState(t, d, s, goal, "open", 0)
			})
		}
	}
}

func TestSecurityGoalProofDuplicateFindingRowsFailClosed(t *testing.T) {
	d, s, goal, node, first := goalProofFixture(t)
	taskID, err := s.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.AddFinding(taskID, node, "legacy duplicate", "duplicate", SeverityHigh, "summary", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(second, FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProveGoal(t.Context(), goal, node); err == nil {
		t.Fatal("arbitrary confirmed duplicate hid a false-positive row")
	}
	assertGoalProofState(t, d, s, goal, "open", 0)
	// A surviving invalid duplicate cannot support another goal either.
	if _, err := d.DeleteFinding(first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProveGoal(t.Context(), goal, node); err == nil {
		t.Fatal("deleting one duplicate bypassed remaining invalid triage")
	}
}

func TestSecurityGoalProofDuplicateTriageDoesNotDeadlock(t *testing.T) {
	d, s, goal, node, first := goalProofFixture(t)
	taskID, err := s.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.AddFinding(taskID, node, "legacy duplicate", "duplicate", SeverityHigh, "summary", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(second, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProveGoal(t.Context(), goal, node); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	transactions := make([]*sql.Tx, 0, 2)
	for _, id := range []int64{first, second} {
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `SELECT id FROM findings WHERE id=$1 FOR UPDATE`, id); err != nil {
			t.Fatal(err)
		}
		transactions = append(transactions, tx)
	}
	done := make(chan error, 2)
	for i, id := range []int64{first, second} {
		go func(tx *sql.Tx, findingID int64) {
			_, _, _, _, err := SetFindingStatusTx(ctx, tx, findingID, FindingFalsePositive)
			if err == nil {
				err = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
			done <- err
		}(transactions[i], id)
	}
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	assertGoalProofState(t, d, s, goal, "open", 0)
}

func TestSecurityGoalProofAttachmentAndTaskDeletionLockOrder(t *testing.T) {
	d, s, _, _, _ := goalProofFixture(t)
	taskID, err := s.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	node, err := s.AddNode(KindFinding, map[string]any{}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	attacher, attachPID := goalProofConnection(t)
	deleter, deletePID := goalProofConnection(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	blocker, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(ctx, `SELECT id FROM exploration_nodes WHERE id=$1 FOR UPDATE`, node); err != nil {
		t.Fatal(err)
	}
	attached, deleted := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := attacher.AddFinding(taskID, node, "attachment", "attachment", SeverityHigh, "summary", "proof", "worker", nil)
		attached <- err
	}()
	waitGoalProofLock(t, d, attachPID, attached)
	go func() { deleted <- deleter.DeleteTask(taskID) }()
	waitGoalProofLock(t, d, deletePID, deleted)
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{attached, deleted} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestSecurityGoalProofSourceDeletionAndDependentTaskDeletion(t *testing.T) {
	for _, mode := range []string{"finding", "intent", "task"} {
		t.Run(mode, func(t *testing.T) {
			d, source, _, node, finding := goalProofFixture(t)
			sourceTask, err := source.TaskID()
			if err != nil {
				t.Fatal(err)
			}
			child, err := d.CreateTaskWithOptions("dependent deletion", "inherited proof", TaskCreateOptions{SourceTaskIDs: []int64{sourceTask}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = d.DeleteTask(child.ID) })
			goal, err := d.Exploration(child.ExplorationID).AddGoal(map[string]any{"text": "inherited proof"}, "human")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.Exploration(child.ExplorationID).ProveGoal(t.Context(), goal, node); err != nil {
				t.Fatal(err)
			}
			intent, err := source.AddIntent(map[string]any{"summary": "source evidence"}, 1, nil, "planner")
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Link(intent, RelYields, node); err != nil {
				t.Fatal(err)
			}
			sourceDelete, sourcePID := goalProofConnection(t)
			childDelete, _ := goalProofConnection(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			prepared, release := make(chan struct{}), make(chan struct{})
			sourceDone, childDone := make(chan error, 1), make(chan error, 1)
			go func() {
				_, err := childDelete.DeleteTaskCascadePrepared(child.ID, false, false, false, func(TaskDeletePreparation) error {
					close(prepared) // Task + assets/anchors table locks are held.
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
				childDone <- err
			}()
			select {
			case <-prepared:
			case err := <-childDone:
				t.Fatalf("dependent deletion failed before barrier: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			go func() {
				var err error
				if mode == "finding" {
					_, err = sourceDelete.DeleteFinding(finding)
				} else if mode == "intent" {
					_, err = sourceDelete.Exploration(source.ID()).CancelIntent(intent)
				} else {
					err = sourceDelete.DeleteTask(sourceTask)
				}
				sourceDone <- err
			}()
			waitGoalProofLock(t, d, sourcePID, sourceDone)
			close(release)
			for _, done := range []<-chan error{sourceDone, childDone} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			var remaining int
			if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE id=ANY($1::bigint[])`, []int64{node, goal}).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatalf("source/goal deletion incomplete: remaining=%d err=%v", remaining, err)
			}
		})
	}
}

func goalProofConnection(t *testing.T) (*DB, int) {
	t.Helper()
	conn, err := sql.Open("pgx", testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = conn.Close() })
	var pid int
	if err := conn.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return &DB{conn}, pid
}

func waitGoalProofLock(t *testing.T, d *DB, pid int, done <-chan error) {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := d.QueryRow(`SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("operation finished before lock barrier: %v", err)
		case <-timeout.C:
			t.Fatal("operation did not reach lock barrier")
		case <-ticker.C:
		}
	}
}
