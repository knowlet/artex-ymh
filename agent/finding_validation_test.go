package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportFindingValidationRejectsMissingFieldsWithoutWrites(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask(t.Name(), "local persistence fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	tools := NewToolSet(d.Exploration(task.ExplorationID), "fixture")
	tools.SetTaskID(task.ID)
	notices := 0
	tools.SetNotifyFinding(func(int64, string) { notices++ })
	for _, raw := range []string{
		`{}`,
		`{"severity":"low","summary":"fixture"}`,
		`{"vulnclass":"fixture","summary":"fixture"}`,
		`{"vulnclass":"fixture","severity":"low"}`,
		`{"vulnclass":"fixture","severity":"low","summary":"  "}`,
	} {
		res, err := tools.addFinding().Call(t.Context(), json.RawMessage(raw), nil)
		if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "no finding recorded") {
			t.Fatalf("invalid report accepted: %s result=%+v err=%v", raw, res, err)
		}
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 || notices != 0 || tools.Writes().Findings != 0 {
		t.Fatalf("invalid report persisted or notified: rows=%d notices=%d writes=%+v", count, notices, tools.Writes())
	}
}
