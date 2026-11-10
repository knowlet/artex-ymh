package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/selfupdate"
)

func TestUpdateAndRollbackShareAdmission(t *testing.T) {
	hub := &updateHub{subs: map[chan updateProgress]struct{}{}}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 32 {
		wg.Go(func() {
			<-start
			var ok bool
			if i%2 == 0 {
				ok = hub.begin("v1.2.3")
			} else {
				ok = hub.beginRollback()
			}
			if ok {
				admitted.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("admitted %d simultaneous mutations", admitted.Load())
	}
	hub.finishRollback(errors.New("fixture failure"))
	if !hub.begin("v1.2.4") {
		t.Fatal("failed operation kept admission closed")
	}
	hub.finish(nil)
	if hub.begin("v1.2.5") || hub.beginRollback() {
		t.Fatal("restart-pending update admitted another mutation")
	}
}

func TestUpdateRoutesRejectWhileRestartPending(t *testing.T) {
	previous := updHub
	hub := &updateHub{subs: map[chan updateProgress]struct{}{}}
	updHub = hub
	t.Cleanup(func() { updHub = previous })
	if !hub.beginRollback() {
		t.Fatal("rollback not admitted")
	}
	hub.finishRollback(nil)
	s := &Server{}
	w := httptest.NewRecorder()
	s.updateApply(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if selfupdate.InstallEnabled {
		if w.Code != http.StatusConflict {
			t.Fatalf("restart-pending apply returned %d", w.Code)
		}
	} else if w.Code != http.StatusForbidden {
		t.Fatalf("install-disabled apply returned %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.updateRollback(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("restart-pending rollback returned %d", w.Code)
	}
}
