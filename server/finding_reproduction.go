package server

import (
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

// resolveFindingTraffic matches reproduction steps to recorded exchanges in the task window.
func (s *Server) resolveFindingTraffic(taskID int64, repro json.RawMessage) json.RawMessage {
	if s.m == nil || taskID <= 0 {
		return repro
	}
	trStore := s.m.Traffic()
	if trStore == nil {
		return repro
	}
	var rp report.Reproduction
	if json.Unmarshal(repro, &rp) != nil || len(rp.Steps) == 0 {
		return repro
	}
	since := time.Now().Add(-24 * time.Hour)
	if tk, err := s.m.pg.GetTask(taskID); err == nil && tk != nil {
		if tk.FirstRunAt != nil {
			since = *tk.FirstRunAt
		} else {
			since = tk.CreatedAt
		}
	}
	refs := make([]traffic.StepRef, len(rp.Steps))
	for i, st := range rp.Steps {
		refs[i] = traffic.StepRef{Request: st.Request, Response: st.Response}
	}
	ids := trStore.ResolveSteps(since.Unix(), time.Now().Unix(), refs)
	for i, id := range ids {
		if id != "" {
			rp.Steps[i].ExchangeID = id
		}
	}
	out, err := json.Marshal(rp)
	if err != nil {
		return repro
	}
	return out
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
	hasResolved := false
	for _, st := range rp.Steps {
		if st.ExchangeID != "" {
			hasResolved = true
			break
		}
	}
	if !hasResolved && s.m != nil && s.m.Traffic() != nil && taskID != nil && *taskID > 0 {
		f, _ := s.m.pg.GetFinding(findingID)
		since := time.Now().Add(-24 * time.Hour)
		if f != nil {
			since = f.CreatedAt
		}
		if tk, err := s.m.pg.GetTask(*taskID); err == nil && tk != nil {
			if tk.FirstRunAt != nil {
				since = *tk.FirstRunAt
			} else if !tk.CreatedAt.IsZero() {
				since = tk.CreatedAt
			}
		}
		refs := make([]traffic.StepRef, len(rp.Steps))
		for i, st := range rp.Steps {
			refs[i] = traffic.StepRef{Request: st.Request, Response: st.Response}
		}
		ids := s.m.Traffic().ResolveSteps(since.Unix(), time.Now().Unix(), refs)
		for i, id := range ids {
			if id != "" {
				rp.Steps[i].ExchangeID = id
			}
		}
	}
	return rp
}
