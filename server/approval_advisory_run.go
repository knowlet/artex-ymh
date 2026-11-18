package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/approvalreview"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
)

type advisoryRunResult struct {
	src     *db.ApprovalAdvisorySource
	current bool
	http    int
}

// runApprovalAdvisoryReview performs one bounded review. It never changes approval status.
func (s *Server) runApprovalAdvisoryReview(parent context.Context, pendingID int64, trigger string) (advisoryRunResult, error) {
	var empty advisoryRunResult
	if s.m == nil || s.m.pg == nil {
		return empty, errors.New("database unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 75*time.Second)
	defer cancel()
	if s.ctx != nil {
		stop := context.AfterFunc(s.ctx, cancel)
		defer stop()
	}
	src, err := s.m.pg.ReadApprovalAdvisory(ctx, pendingID)
	if err != nil {
		return empty, err
	}
	if src == nil {
		return empty, errAdvisoryNotFound
	}
	if src.Status != "pending" {
		return advisoryRunResult{src: src}, errAdvisorySettled
	}
	cfg, _ := s.m.pg.ReadAdvisoryAutoConfig(ctx)
	meta, _ := s.m.pg.ReadAdvisoryAutoMeta(ctx, pendingID)
	if trigger == "auto" && meta != nil && meta.Cancelled {
		return advisoryRunResult{src: src}, errAdvisoryCancelled
	}
	prep, err := prepareApprovalAdvisory(ctx, s.m.pg, src)
	if err != nil {
		return empty, err
	}
	if trigger == "auto" && !advisoryNeedsWork(src, prep, trigger, meta, cfg.MaxRetries) {
		return advisoryRunResult{src: src, current: advisoryIsCurrent(src, prep)}, nil
	}
	release, ok, err := s.m.pg.TryAdvisoryGlobalSlot(ctx, cfg.GlobalSlots)
	if err != nil {
		return empty, err
	}
	if !ok {
		return empty, errAdvisoryBusy
	}
	defer release()
	attempt, claimed, err := s.m.pg.ClaimApprovalAdvisory(ctx, src.ID, db.ApprovalAdvisory{
		Trigger: trigger, Fingerprint: prep.fingerprint, ActionFingerprint: src.Fingerprint(),
		ProfileID: prep.profileID, Model: prep.model, ProfileVersion: prep.profileVersion,
	}, prep.timeout)
	if err != nil {
		return empty, err
	}
	if !claimed {
		current := attempt.Fingerprint == prep.fingerprint && attempt.State == "succeeded"
		status := http.StatusOK
		if attempt.State == "running" {
			status = http.StatusAccepted
		}
		return advisoryRunResult{src: &db.ApprovalAdvisorySource{ID: src.ID, Status: src.Status, Advisory: attempt}, current: current, http: status}, nil
	}
	if trigger == "auto" {
		consumed, err := s.m.pg.ConsumeAdvisoryDailyBudget(ctx, cfg.DailyBudget)
		if err != nil {
			return empty, err
		}
		if !consumed {
			return empty, errAdvisoryBudget
		}
	}
	errorCode := ""
	var result *approvalreview.Result
	prov, cfgEntry, available := s.providerForProfile(prep.profileID)
	if !available {
		errorCode = "provider_unavailable"
	} else if cfgEntry.Model != prep.model || cfgEntry.Stream != prep.streaming {
		errorCode = "policy_unavailable"
	} else {
		check, checkErr := prepareApprovalAdvisory(ctx, s.m.pg, src)
		if checkErr != nil || check.fingerprint != prep.fingerprint {
			errorCode = "policy_unavailable"
		} else if meta, _ := s.m.pg.ReadAdvisoryAutoMeta(ctx, pendingID); meta != nil && meta.Cancelled {
			errorCode = "cancelled"
		} else {
			callCtx, callCancel := context.WithTimeout(ctx, prep.timeout)
			value, callErr := runApprovalAdvisory(llmrec.WithWorker(callCtx, judgeWorkerLane), prov, prep.input, prep.streaming)
			callCancel()
			if callErr != nil {
				switch {
				case errors.Is(callErr, context.DeadlineExceeded):
					errorCode = "timeout"
				case errors.Is(callErr, context.Canceled):
					errorCode = "cancelled"
				default:
					errorCode = "invalid_response"
				}
			} else {
				result = &value
			}
		}
	}
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer finishCancel()
	stale := false
	if result != nil {
		latest, readErr := s.m.pg.ReadApprovalAdvisory(finishCtx, src.ID)
		if readErr != nil {
			errorCode = "policy_unavailable"
			result = nil
		} else if latest == nil || latest.Status != "pending" {
			stale = true
		} else if meta, _ := s.m.pg.ReadAdvisoryAutoMeta(finishCtx, src.ID); meta != nil && meta.Cancelled {
			stale = true
			errorCode = "cancelled"
			result = nil
		} else {
			check, checkErr := prepareApprovalAdvisory(finishCtx, s.m.pg, latest)
			if checkErr != nil {
				errorCode = "policy_unavailable"
				result = nil
			} else {
				stale = check.fingerprint != prep.fingerprint
			}
		}
	}
	okFinish, err := s.m.pg.FinishApprovalAdvisory(finishCtx, src.ID, attempt.LeaseID, result, errorCode, stale)
	if err != nil {
		return empty, err
	}
	if !okFinish {
		// Lost lease race — re-read without treating as authorization.
		latest, readErr := s.m.pg.ReadApprovalAdvisory(finishCtx, src.ID)
		if readErr != nil || latest == nil {
			return empty, readErr
		}
		return advisoryRunResult{src: latest, current: advisoryIsCurrent(latest, prep)}, nil
	}
	if trigger == "auto" && (errorCode != "" || stale) {
		_ = s.m.pg.RecordAdvisoryAutoFailure(finishCtx, src.ID, errorCode, cfg.MaxRetries)
	}
	latest, err := s.m.pg.ReadApprovalAdvisory(finishCtx, src.ID)
	if err != nil || latest == nil {
		return empty, err
	}
	current := !stale && errorCode == "" && latest.Advisory != nil && latest.Advisory.LeaseID == attempt.LeaseID && latest.Advisory.State == "succeeded"
	return advisoryRunResult{src: latest, current: current, http: http.StatusOK}, nil
}

var (
	errAdvisoryNotFound  = errors.New("advisory not found")
	errAdvisorySettled   = errors.New("advisory settled")
	errAdvisoryCancelled = errors.New("advisory auto cancelled")
	errAdvisoryBusy      = errors.New("advisory capacity busy")
	errAdvisoryBudget    = errors.New("advisory daily budget exhausted")
)

func advisoryIsCurrent(src *db.ApprovalAdvisorySource, prep advisoryPreparation) bool {
	if src == nil || src.Advisory == nil || src.Status != "pending" || src.Advisory.State != "succeeded" {
		return false
	}
	return prep.fingerprint == src.Advisory.Fingerprint && src.Fingerprint() == src.Advisory.ActionFingerprint
}

func advisoryNeedsWork(src *db.ApprovalAdvisorySource, prep advisoryPreparation, trigger string, meta *db.AdvisoryAutoMeta, maxRetries int) bool {
	if src == nil || src.Status != "pending" {
		return false
	}
	now := time.Now()
	if src.Advisory == nil {
		return trigger == "auto"
	}
	a := src.Advisory
	switch a.State {
	case "running":
		return now.After(a.LeaseUntil)
	case "failed", "stale":
		if trigger == "manual" {
			return true
		}
		if meta != nil && meta.Cancelled {
			return false
		}
		if meta != nil && meta.Attempts > maxRetries {
			return false
		}
		if meta != nil && meta.NextRetryAt != nil && now.Before(*meta.NextRetryAt) {
			return false
		}
		return trigger == "auto"
	case "succeeded":
		return prep.fingerprint != a.Fingerprint || src.Fingerprint() != a.ActionFingerprint
	default:
		return false
	}
}
