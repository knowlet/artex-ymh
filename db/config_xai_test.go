package db

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/xaioauth"
)

func TestXAISubscriptionRejectsAPIKeyAndForeignEndpoint(t *testing.T) {
	for _, profile := range []LLMProfile{
		{Format: xaioauth.Provider, APIKey: "paid-secret"},
		{Format: xaioauth.Provider, BaseURL: "https://other.invalid/v1"},
		{Format: xaioauth.Provider, SessionHeaderKey: "Authorization"},
	} {
		var d DB
		if _, err := d.SaveProfile(&profile); err == nil {
			t.Fatal("unsafe subscription profile was accepted")
		}
	}
}

func TestXAISubscriptionProfilePG(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p := &LLMProfile{Name: "t-grok-subscription-transition", Format: "openai", Model: "m", APIKey: "old-paid-secret"}
	id, err := d.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id); err != nil {
			t.Errorf("clean subscription fixture: %v", err)
		}
	}()
	// Switching auth mechanisms must clear, rather than retain, the old API key.
	p.ID, p.Format, p.APIKey, p.Model = id, xaioauth.Provider, "", ""
	p.APIKeyHint = "must-not-persist"
	if _, err := d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	got, err := d.ProfileByID(id)
	if err != nil || got == nil {
		t.Fatalf("read subscription: %v", err)
	}
	if got.APIKey != "" || got.Format != xaioauth.Provider || got.Model != xaioauth.DefaultModel || got.BaseURL != xaioauth.APIBaseURL || !got.PoolExclude {
		t.Fatalf("invalid persisted subscription: %+v", got)
	}
	profiles, err := d.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range profiles {
		if profile.ID != id {
			continue
		}
		encoded, _ := json.Marshal(profile)
		if profile.APIKeyHint != "" || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "must-not-persist") {
			t.Fatalf("credential hint persisted into subscription DTO: %s", encoded)
		}
	}
	pool, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range pool {
		if member.ID == id {
			t.Fatal("subscription silently joined an API-key fallback pool")
		}
	}
	// An explicit conversion back to paid mode must require a new API key.
	p.Format, p.BaseURL = "openai-responses", "https://api.x.ai/v1"
	if _, err := d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	got, err = d.ProfileByID(id)
	if err != nil || got.APIKey != "" {
		t.Fatalf("old key resurrected after leaving OAuth: %+v, %v", got, err)
	}
	p.APIKey = "new-paid-key"
	if _, err := d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	got, err = d.ProfileByID(id)
	if err != nil || got.APIKey != p.APIKey {
		t.Fatalf("explicit API-key mode stopped working: %+v, %v", got, err)
	}
}
