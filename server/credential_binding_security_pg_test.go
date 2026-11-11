package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/endpoint"
)

func credentialSecurityPG(t *testing.T) *Server {
	t.Helper()
	s, _ := authSecurityPG(t)
	// Execute the actual production table definition inside the isolated schema.
	raw, err := os.ReadFile("../db/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(raw), "CREATE TABLE IF NOT EXISTS llm_profiles (")
	if start < 0 {
		t.Fatal("LLM profile table definition missing")
	}
	end := strings.Index(string(raw[start:]), "\n);")
	if end < 0 {
		t.Fatal("LLM profile table definition incomplete")
	}
	if _, err := s.m.pg.Exec(string(raw[start : start+end+3])); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSecurityPGProfileRequiresReplacementKeyForDestinationChange(t *testing.T) {
	s := credentialSecurityPG(t)
	p := db.LLMProfile{Name: "fixture", Format: "openai", Model: "fixture", BaseURL: "http://localhost:11434/v1", APIKey: "synthetic-stored-key"}
	id, err := s.m.pg.SaveProfile(&p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID, p.APIKey = id, ""
	p.BaseURL = "http://localhost:11435/v1"
	if _, err := s.m.pg.SaveProfile(&p); !errors.Is(err, endpoint.ErrCredentialDestination) {
		t.Fatalf("changed destination reused key: %v", err)
	}
	stored, err := s.m.pg.ProfileByID(id)
	if err != nil || stored.BaseURL != "http://localhost:11434/v1" || stored.APIKey != "synthetic-stored-key" {
		t.Fatal("rejected edit changed stored destination/key")
	}
	p.BaseURL = "http://LOCALHOST:11434/v1/"
	if _, err := s.m.pg.SaveProfile(&p); err != nil {
		t.Fatalf("equivalent local endpoint rejected: %v", err)
	}
	p.BaseURL, p.APIKey = "http://localhost:11435/v1", "synthetic-new-key"
	if _, err := s.m.pg.SaveProfile(&p); err != nil {
		t.Fatalf("explicit replacement rejected: %v", err)
	}
	stored, err = s.m.pg.ProfileByID(id)
	if err != nil || stored.BaseURL != p.BaseURL || stored.APIKey != p.APIKey {
		t.Fatal("explicit destination/key did not commit together")
	}
}

func TestSecurityPGModelsAndTestCannotRedirectProfileKey(t *testing.T) {
	s := credentialSecurityPG(t)
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer upstream.Close()
	id, err := s.m.pg.SaveProfile(&db.LLMProfile{Name: "fixture", Format: "openai", Model: "fixture", BaseURL: "http://localhost:11434/v1", APIKey: "synthetic-stored-key"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"provider": "openai", "model": "fixture", "base_url": upstream.URL, "profile_id": id})
	for _, handler := range []http.HandlerFunc{s.pgListModels, s.testLLM} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("POST", "/api/llm/test", bytes.NewReader(raw)))
		if w.Code != 400 {
			t.Fatalf("profile-key redirect returned %d", w.Code)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("profile key redirect reached receiving endpoint")
	}
}
