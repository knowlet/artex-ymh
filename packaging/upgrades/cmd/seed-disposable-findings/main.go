// seed-disposable-findings seeds a deterministic exploration finding for upgrade E2E only.
// Requires disposable ARTEX_PG_DSN and ARTEX_DATA_DIR (same tree as the running artex process).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
)

const (
	taskDesc       = "upgrade-e2e-disposable-findings-a947"
	taskGoal       = "synthetic fixture for findings export + report workflow"
	findingSummary = "UPGRADE-E2E-FINDING-a947"
	findingName    = "Upgrade E2E Disposable Finding"
	findingReport  = "## Upgrade E2E report\n\nDeterministic disposable seed marker: UPGRADE-E2E-REPORT-a947.\n"
)

type seedOutput struct {
	TaskID           string `json:"task_id"`
	FindingID        int64  `json:"finding_id"`
	FindingNodeID    int64  `json:"finding_node_id"`
	SummaryMarker    string `json:"summary_marker"`
	ReportMarker     string `json:"report_marker"`
	TaskDesc         string `json:"task_desc"`
	UploadFixtureSHA string `json:"upload_fixture_sha256"`
}

func main() {
	if os.Getenv("ARTEX_DATA_DIR") == "" {
		fmt.Fprintln(os.Stderr, "ARTEX_DATA_DIR is required")
		os.Exit(2)
	}
	dsn, _, err := db.DSN()
	if err != nil {
		fmt.Fprintln(os.Stderr, "dsn:", err)
		os.Exit(2)
	}
	dir := os.Getenv("ARTEX_DATA_DIR")
	pg, err := db.Open(dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer pg.Close()

	ctx := context.Background()
	task, err := pg.CreateTask(taskDesc, taskGoal, nil, 0, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create task:", err)
		os.Exit(1)
	}
	store := evidence.New(pg, nil, dir)
	input := db.RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, Worker: "upgrade-e2e",
		VulnClass: "TEST", Summary: findingSummary, Name: findingName, Severity: "low",
	}
	rec, err := store.Record(ctx, input, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "record finding:", err)
		os.Exit(1)
	}
	if _, err = pg.SetFindingReportByNodeID(rec.NodeID, findingReport); err != nil {
		fmt.Fprintln(os.Stderr, "set report:", err)
		os.Exit(1)
	}

	out := seedOutput{
		TaskID: fmt.Sprint(task.ID), FindingID: rec.FindingID, FindingNodeID: rec.NodeID,
		SummaryMarker: findingSummary, ReportMarker: "UPGRADE-E2E-REPORT-a947",
		TaskDesc: taskDesc,
	}
	if fp := os.Getenv("ARTEX_UPLOAD_FIXTURE"); fp != "" {
		if b, err := os.ReadFile(fp); err == nil {
			sum := sha256.Sum256(b)
			out.UploadFixtureSHA = hex.EncodeToString(sum[:])
		}
	}

	payload, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err = os.Stdout.Write(append(payload, '\n')); err != nil {
		os.Exit(1)
	}
	if outPath := os.Getenv("ARTEX_FINDINGS_SEED_OUT"); outPath != "" {
		if err := os.WriteFile(outPath, payload, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, outPath, err)
			os.Exit(1)
		}
	}
}
