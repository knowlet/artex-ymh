package server

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestWaitBackgroundWorkersReturnsWhenArchiveWorkerStuck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ctx: ctx}
	s.archiveWG.Add(1)
	cancel()
	returned := make(chan struct{})
	go func() {
		s.WaitBackgroundWorkers()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("restart blocked on a stuck archive worker")
	}
	s.archiveWG.Done()
}

func TestWaitBackgroundWorkersWaitsForSideSnapshotFlush(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		flushing := make(chan struct{})
		s := &Server{side: &sideQuestionState{done: flushing}}
		returned := make(chan struct{})
		go func() { s.WaitBackgroundWorkers(); close(returned) }()
		synctest.Wait()
		select {
		case <-returned:
			t.Fatal("database teardown could precede side snapshot flush")
		default:
		}
		close(flushing)
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Fatal("shutdown did not finish after flush")
		}
	})
}
