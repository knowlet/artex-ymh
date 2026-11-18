package server

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

func (s *Server) startApprovalAdvisoryWorker(ctx context.Context) {
	go func() {
		// Startup recovery: first tick soon after boot.
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			s.advisoryWorkerTick(ctx, &wg)
			timer.Reset(4 * time.Second)
		}
	}()
}

func (s *Server) advisoryWorkerTick(ctx context.Context, wg *sync.WaitGroup) {
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
		log.Printf("[advisory-auto] list: %v", err)
		return
	}
	launched := 0
	for _, id := range ids {
		if launched >= 4 {
			break
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
				log.Printf("[advisory-auto] pending=%d: %v", id, err)
			case res.src != nil && res.src.Advisory != nil:
				log.Printf("[advisory-auto] pending=%d state=%s", id, res.src.Advisory.State)
			}
		}()
	}
}
