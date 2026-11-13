package server

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/traffic"
)

func (s *Server) seedFindingReproductionTools() {
	const flag = "finding_reproduction_v1"
	if value, _, _ := s.m.pg.GetSetting(flag); value == "true" {
		return
	}
	row, err := s.m.pg.GetTool("report_finding")
	if err != nil || row == nil || !row.System {
		log.Printf("[reproduction] load report_finding: %v", err)
		return
	}
	var schema map[string]any
	if err := json.Unmarshal(row.Schema, &schema); err != nil {
		return
	}
	props := objectProperty(schema, "properties")
	if _, exists := props["reproduction"]; !exists {
		props["reproduction"] = agent.ReproductionToolSchema()
	}
	raw, _ := json.Marshal(schema)
	result, err := s.m.pg.Exec(`UPDATE tools SET schema=$2::jsonb,updated_at=now() WHERE key=$1 AND system AND schema=$3::jsonb`,
		"report_finding", string(raw), string(row.Schema))
	if err != nil {
		log.Printf("[reproduction] upgrade report_finding schema: %v", err)
		return
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

func (s *Server) taskReproWindow(taskID int64) (since time.Time, ok bool) {
	if s.m == nil || taskID <= 0 {
		return time.Time{}, false
	}
	tk, err := s.m.pg.GetTask(taskID)
	if err != nil || tk == nil {
		return time.Time{}, false
	}
	since = tk.CreatedAt
	if tk.FirstRunAt != nil {
		since = *tk.FirstRunAt
	}
	return since, true
}

// taskTrafficResolver binds report_finding reproduction linking to a specific task's
// traffic index (per-task MITM when enabled).
func (s *Server) taskTrafficResolver(taskID int64) func(int64, json.RawMessage) json.RawMessage {
	return func(_ int64, repro json.RawMessage) json.RawMessage {
		return s.resolveFindingTraffic(taskID, repro)
	}
}

// resolveFindingTraffic matches reproduction steps to recorded exchanges in the task window.
func (s *Server) resolveFindingTraffic(taskID int64, repro json.RawMessage) json.RawMessage {
	if s.m == nil || taskID <= 0 {
		return repro
	}
	trStore := s.m.TrafficStoreForTask(context.Background(), taskID)
	if trStore == nil {
		return repro
	}
	var rp report.Reproduction
	if json.Unmarshal(repro, &rp) != nil || len(rp.Steps) == 0 {
		return repro
	}
	since, ok := s.taskReproWindow(taskID)
	if !ok {
		return repro
	}
	linkReproductionSteps(trStore, since.Unix(), time.Now().Unix(), &rp)
	out, err := json.Marshal(rp)
	if err != nil {
		return repro
	}
	return out
}

func reproStepRefs(rp report.Reproduction) []traffic.StepRef {
	refs := make([]traffic.StepRef, len(rp.Steps))
	for i, st := range rp.Steps {
		refs[i] = traffic.StepRef{Request: st.Request, Response: st.Response, ExchangeID: st.ExchangeID}
	}
	return refs
}

func (s *Server) reproductionForFinding(findingID int64, raw json.RawMessage, taskID *int64) any {
	if len(raw) < 3 {
		return nil
	}
	var rp report.Reproduction
	if json.Unmarshal(raw, &rp) != nil {
		var anyVal any
		_ = json.Unmarshal(raw, &anyVal)
		return anyVal
	}
	needResolve := false
	for _, st := range rp.Steps {
		if st.ExchangeID == "" {
			needResolve = true
			break
		}
	}
	if needResolve && s.m != nil && taskID != nil && *taskID > 0 {
		trStore := s.m.TrafficStoreExistingForTask(*taskID)
		since, ok := s.taskReproWindow(*taskID)
		if trStore != nil && ok {
			linkReproductionSteps(trStore, since.Unix(), time.Now().Unix(), &rp)
		}
	}
	return rp
}

func linkReproductionSteps(trStore *traffic.Traffic, sinceUnix, untilUnix int64, rp *report.Reproduction) {
	if trStore == nil || rp == nil {
		return
	}
	refs := reproStepRefs(*rp)
	ids := trStore.ResolveSteps(sinceUnix, untilUnix, refs)
	for i, id := range ids {
		if id != "" && rp.Steps[i].ExchangeID == "" {
			rp.Steps[i].ExchangeID = id
		}
	}
}
