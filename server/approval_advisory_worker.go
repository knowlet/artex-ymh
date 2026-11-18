package server

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

func (s *Server) startApprovalAdvisoryWorker(ctx context.Context) {
	if ctx == nil {
		ctx = s.ctx
	}
	s.advisoryWG.Add(1)
	go func() {
		defer s.advisoryWG.Done()
		// Startup recovery: first tick soon after boot.
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		var reviewWG sync.WaitGroup
		for {
			select {
			case <-ctx.Done():
				reviewWG.Wait()
				return
			case <-timer.C:
			}
			if ctx.Err() != nil {
				reviewWG.Wait()
				return
			}
			s.advisoryWorkerTick(ctx, &reviewWG)
			timer.Reset(4 * time.Second)
		}
	}()
}

// backgroundWorkerShutdownGrace bounds how long restart waits for in-flight archive
// work after the server root context is cancelled. Snapshot paths observe that context,
// but a blocked advisory lock or orphaned goroutine must not hold the process open forever.
const backgroundWorkerShutdownGrace = 45 * time.Second

func waitBackgroundWork(ctx context.Context, grace time.Duration, label string, work func()) {
	if work == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		work()
		close(done)
	}()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
		log.Printf("[shutdown] %s still running after stop: %v", label, ctx.Err())
	case <-timer.C:
		log.Printf("[shutdown] %s grace period expired", label)
	}
}

// WaitBackgroundWorkers blocks until ctx-scoped background loops exit. Call after
// cancelling the Server root context and before closing the database.
func (s *Server) WaitBackgroundWorkers() {
	if s == nil {
		return
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	waitBackgroundWork(ctx, backgroundWorkerShutdownGrace, "advisory-auto", s.advisoryWG.Wait)
	waitBackgroundWork(ctx, backgroundWorkerShutdownGrace, "task-archive", s.archiveWG.Wait)
	if s.side != nil {
		waitBackgroundWork(ctx, backgroundWorkerShutdownGrace, "side-snapshot", func() { <-s.side.done })
	}
}

func (s *Server) advisoryWorkerTick(ctx context.Context, wg *sync.WaitGroup) {
	if ctx.Err() != nil {
		return
	}
	if s.m == nil || s.m.pg == nil {
		return
	}
	tickCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cfg, err := s.m.pg.ReadAdvisoryAutoConfig(tickCtx)
	if err != nil || !cfg.Ready {
		return
	}
	if cfg.DailyUsed >= cfg.DailyBudget {
		return
	}
	ids, err := s.m.pg.ListPendingIDsForAutoAdvisory(tickCtx, 32)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("[advisory-auto] list: %v", err)
		}
		return
	}
	launched := 0
	for _, id := range ids {
		if launched >= 4 {
			break
		}
		if ctx.Err() != nil {
			return
		}
		id := id
		src, err := s.m.pg.ReadApprovalAdvisory(tickCtx, id)
		if err != nil || src == nil || src.Status != "pending" {
			continue
		}
		meta, _ := s.m.pg.ReadAdvisoryAutoMeta(tickCtx, id)
		if meta != nil && meta.Cancelled {
			continue
		}
		if meta != nil && meta.NextRetryAt != nil && time.Now().Before(*meta.NextRetryAt) {
			continue
		}
		prep, err := prepareApprovalAdvisory(tickCtx, s.m.pg, src)
		if err != nil {
			continue
		}
		if meta != nil && meta.Attempts > cfg.MaxRetries {
			continue
		}
		if !advisoryNeedsWork(src, prep, "auto", meta, cfg.MaxRetries) {
			continue
		}
		if src.Advisory != nil && src.Advisory.State == "succeeded" && advisoryIsCurrent(src, prep) {
			continue
		}
		launched++
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.runApprovalAdvisoryReview(ctx, id, "auto")
			switch {
			case errors.Is(err, errAdvisoryBusy), errors.Is(err, errAdvisoryBudget):
				return
			case err != nil:
				if ctx.Err() == nil {
					log.Printf("[advisory-auto] pending=%d: %v", id, err)
				}
			case res.src != nil && res.src.Advisory != nil:
				if ctx.Err() == nil {
					log.Printf("[advisory-auto] pending=%d state=%s", id, res.src.Advisory.State)
				}
			}
		}()
	}
}
