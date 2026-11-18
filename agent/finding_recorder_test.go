package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
)

type failingFindingRecorder struct{}

func (failingFindingRecorder) Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error) {
	return nil, errors.New("fixture persistence failed")
}

func TestReportFindingOptionalTrafficWithoutCapture(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("TCP evidence", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	ts.SetFindingRecorder(evidence.New(d, nil, t.TempDir()))
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	for _, refs := range []string{"", `,"traffic_refs":[]`, `,"traffic_refs":null`} {
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(`{"vulnclass":"TCP","severity":"low","summary":"verified TCP fixture","evidence":"command output proves the finding"`+refs+`}`), nil)
		if err != nil || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
			t.Fatalf("optional traffic rejected: %v %s", err, res.Flatten())
		}
		var out db.RecordedFinding
		if err := json.Unmarshal([]byte(strings.SplitN(res.Flatten(), "\n", 2)[1]), &out); err != nil {
			t.Fatal(err)
		}
		f, err := d.GetFinding(out.FindingID)
		if err != nil || f == nil || len(out.Traffic.Bindings) != 0 || f.Evidence != "command output proves the finding" {
			t.Fatalf("lost non-HTTP evidence: %+v %v", f, err)
		}
	}
	if notices != 3 {
		t.Fatalf("successful reports notified %d times", notices)
	}
}

func TestReportFindingAtomicContract(t *testing.T) {
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return true }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("report contract", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts = d.Exploration(task.ExplorationID)
	ts.taskID = task.ID
	ts.worker = "fixture"
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	call := func(body string) string {
		t.Helper()
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}
	ts.SetFindingRecorder(failingFindingRecorder{})
	if got := call(`{"vulnclass":"TEST","summary":"fail","severity":"low","traffic_refs":[{"traffic_id":"x"}]}`); !strings.Contains(got, "persistence failed") {
		t.Fatal(got)
	}
	if notices != 0 || ts.writes.Findings != 0 {
		t.Fatal("notified before commit")
	}
	ts.SetFindingRecorder(nil)
	got := call(`{"vulnclass":"TEST","summary":"legacy report","severity":"low"}`)
	lines := strings.SplitN(got, "\n", 2)
	if len(lines) != 2 {
		t.Fatal(got)
	}
	var out db.RecordedFinding
	if err = json.Unmarshal([]byte(lines[1]), &out); err != nil {
		t.Fatal(err)
	}
	if lines[0] != fmt.Sprintf("finding recorded: %d", out.NodeID) || out.FindingID <= 0 || notices != 1 {
		t.Fatal(got)
	}
	f, err := d.GetFinding(out.FindingID)
	if err != nil || f == nil || f.NodeID == nil || *f.NodeID != out.NodeID {
		t.Fatalf("wrong finding/node mapping: %+v %v", f, err)
	}
	if got = call(`{"vulnclass":"TEST","summary":"no storage","severity":"low","traffic_refs":[{"traffic_id":"x"}]}`); !strings.Contains(got, "未登记") {
		t.Fatal(got)
	}
	if notices != 1 {
		t.Fatal("failed tool triggered reporter")
	}
}

func TestReportFindingWrappedCallsPersist(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("wrapped finding", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	intent, err := d.Exploration(task.ExplorationID).AddIntent(map[string]any{"summary": "exploit fixture"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(d.Exploration(task.ExplorationID), "work#1")
	ts.SetTaskID(task.ID)
	ts.SetOwnerNode(intent)
	raw := json.RawMessage(fmt.Sprintf(`{"vulnclass":"auth","severity":"medium","summary":"session replay works","evidence":"whoami","intent_id":%d}`, intent))
	for i := 0; i < 3; i++ {
		var value any = raw
		if i > 0 {
			value = string(raw)
		}
		wrapped, err := json.Marshal(map[string]any{"arguments": value})
		if err != nil {
			t.Fatal(err)
		}
		raw = wrapped
	}
	res, err := ts.addFinding().Call(t.Context(), raw, nil)
	if err != nil || res.IsError || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
		t.Fatalf("wrapped report_finding failed: %+v err=%v", res, err)
	}
	var count int
	if err := d.QueryRow(`SELECT COUNT(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("finding count=%d err=%v", count, err)
	}
	var class, severity, summary, evidence string
	if err := d.QueryRow(`SELECT vulnclass,severity,summary,evidence FROM findings WHERE task_id=$1`, task.ID).
		Scan(&class, &severity, &summary, &evidence); err != nil {
		t.Fatal(err)
	}
	if class != "auth" || severity != "medium" || summary != "session replay works" || evidence != "whoami" {
		t.Fatalf("wrapped finding fields lost: class=%q severity=%q summary=%q evidence=%q", class, severity, summary, evidence)
	}
}
