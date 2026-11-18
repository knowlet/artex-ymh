package server

import (
	"testing"
	"time"
)

func TestWaitBackgroundWorkersWaitsForSideSnapshotFlush(t *testing.T) {
	flushing := make(chan struct{})
	s := &Server{side: &sideQuestionState{done: flushing}}
	returned := make(chan struct{})
	go func() { s.WaitBackgroundWorkers(); close(returned) }()
	select {
	case <-returned:
		t.Fatal("database teardown could precede side snapshot flush")
	case <-time.After(30 * time.Millisecond):
	}
	close(flushing)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after flush")
	}
}
