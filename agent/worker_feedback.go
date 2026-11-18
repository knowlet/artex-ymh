package agent

import "github.com/Autumn-27/artex/db"

// latestWorkerOutput is shared by the completion trigger and the explicit
// get_worker_output tool, so both choose the same authoritative final text.
func latestWorkerOutput(ts *db.ExplorationStore, intentID int64) (*db.Activity, error) {
	return ts.LatestWorkerOutputWithSources(intentID)
}

// recentWorkerFeedback is automatically refreshed in each overview. Keep
// worker/tool-controlled excerpts inside untrusted-data delimiters; the store's
// bounded factual metadata carries step IDs for optional full-evidence reads.
func recentWorkerFeedback(ts *db.ExplorationStore) ([]db.WorkerFeedback, error) {
	feedback, err := ts.RecentWorkerFeedback(6)
	if err != nil {
		return nil, err
	}
	for i := range feedback {
		if output := feedback[i].LatestOutput; output != nil {
			output.Excerpt = WrapUntrustedData("worker-output", output.Excerpt)
		}
		for j := range feedback[i].RecentErrors {
			failure := &feedback[i].RecentErrors[j]
			failure.Excerpt = WrapUntrustedData("tool-output", failure.Excerpt)
		}
	}
	return feedback, nil
}
