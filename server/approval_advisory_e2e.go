// Advisory E2E harness helpers (Playwright / local disposable PG only).
// Does not change production authorization paths.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"golang.org/x/crypto/bcrypt"
)

// AdvisoryE2EBootstrap seeds auth, judge profile, fake provider, two pending rows and auto config.
// autoPendingID is for the queued→running path; cancelPendingID is isolated for cancel UX checks.
func (s *Server) AdvisoryE2EBootstrap(ctx context.Context, fake llm.Provider, model string) (token string, autoPendingID, cancelPendingID int64, err error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return "", 0, 0, fmt.Errorf("server database unavailable")
	}
	pg := s.m.pg
	const profileID int64 = 42
	if err := seedAdvisoryE2ESchema(pg); err != nil {
		return "", 0, 0, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("e2e-advisory-pass"), bcrypt.DefaultCost)
	if err != nil {
		return "", 0, 0, err
	}
	if err := pg.SetSetting(authPassKey, string(hash)); err != nil {
		return "", 0, 0, err
	}
	if err := pg.SetSetting("llm_judge_profile_id", "42"); err != nil {
		return "", 0, 0, err
	}
	s.ctx = ctx
	s.provCacheMu.Lock()
	if s.provByProfile == nil {
		s.provByProfile = map[int64]*provEntry{}
	}
	s.provByProfile[profileID] = &provEntry{prov: fake, cfg: agent.Config{Model: model, Stream: false}}
	s.provCacheMu.Unlock()
	consent := time.Now().UTC()
	if err := pg.SaveAdvisoryAutoConfig(db.AdvisoryAutoConfig{
		Enabled: true, ConsentAt: consent, GlobalSlots: 8, MaxRetries: 3, DailyBudget: 50,
	}); err != nil {
		return "", 0, 0, err
	}
	modelInput := json.RawMessage(`{"version":4,"tool_name":"Write","arguments":{"file_path":"e2e.txt","content":"fixture"}}`)
	audit := &db.InterceptAudit{
		InitialAction: "ask", Correlation: "exact", InputDigest: "e2e", UserMessage: "e2e",
		ExecutionStatus: "not_started", CapturedAt: time.Now().UTC(), ModelInput: modelInput,
	}
	autoPendingID, err = pg.CreateInterceptPending(1, 0, "", "e2e", "Write", []byte(`{"file_path":"e2e-auto.txt","content":"auto"}`), "e2e auto",
		audit)
	if err != nil {
		return "", 0, 0, err
	}
	cancelPendingID, err = pg.CreateInterceptPending(1, 0, "", "e2e", "Write", []byte(`{"file_path":"e2e-cancel.txt","content":"cancel"}`), "e2e cancel",
		audit)
	if err != nil {
		return "", 0, 0, err
	}
	// Keep worker from finishing before Playwright asserts cancel UX; cancel test still POSTs idempotent cancel.
	if err := pg.CancelApprovalAdvisoryAuto(ctx, cancelPendingID); err != nil {
		return "", 0, 0, err
	}
	token, err = signJWT(s.jwtKey, 0)
	if err != nil {
		return "", 0, 0, err
	}
	return token, autoPendingID, cancelPendingID, nil
}

func seedAdvisoryE2ESchema(pg *db.DB) error {
	_, err := pg.Exec(`INSERT INTO llm_profiles(id,name,format,model,streaming,is_default,updated_at)
		VALUES(42,'e2e','openai','e2e-fixture',false,true,now())
		ON CONFLICT (id) DO UPDATE SET model=EXCLUDED.model, name=EXCLUDED.name, format=EXCLUDED.format`)
	if err != nil {
		return err
	}
	_, err = pg.Exec(`INSERT INTO intercept_rules(id,name,enabled,priority,match_target,match_type,pattern,action,message,timeout_enabled,timeout_seconds,timeout_action,builtin)
		VALUES(1,'e2e',true,10,'tool_name','string','Write','ask','e2e',false,300,'deny',true)
		ON CONFLICT (id) DO NOTHING`)
	return err
}

// WriteAdvisoryE2EEnv writes env vars for the Playwright runner.
func WriteAdvisoryE2EEnv(path, baseURL, token string, autoPendingID, cancelPendingID int64) error {
	body := fmt.Sprintf("ADVISORY_E2E_BASE_URL=%s\nADVISORY_E2E_TOKEN=%s\nADVISORY_E2E_PENDING_ID=%d\nADVISORY_E2E_CANCEL_PENDING_ID=%d\n",
		baseURL, token, autoPendingID, cancelPendingID)
	return os.WriteFile(path, []byte(body), 0600)
}
