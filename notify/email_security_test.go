package notify

import (
	"context"
	"strings"
	"testing"
)

func TestEmailRequiresSTARTTLSBeforeEnvelopeOrBody(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)
	delete(cfg, "allow_insecure") // default protects anonymous relay mail too
	_, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("unencrypted SMTP was not rejected: %v", err)
	}
	if f.sawCommand("MAIL") || f.sawCommand("RCPT") || f.sawCommand("DATA") || f.body() != "" {
		t.Fatal("mail data was sent before enforcing TLS")
	}
}

func TestEmailExplicitPlaintextRelayStillWorks(t *testing.T) {
	f := newFakeSMTP(t)
	if _, err := (emailChannel{}).Send(context.Background(), emailCfg(t, f, map[string]any{"allow_insecure": true}), singleMsg()); err != nil {
		t.Fatal(err)
	}
	if !f.sawCommand("DATA") || f.body() == "" {
		t.Fatal("explicit plaintext relay did not receive mail")
	}
}

func TestEmailTLSFailureNeverFallsBackToPlaintext(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "STARTTLS", true: "implicit TLS"}[implicit], func(t *testing.T) {
			f := newFakeSMTP(t)
			f.advertiseSTARTTLS = !implicit
			cfg := emailCfg(t, f, map[string]any{"tls": implicit, "allow_insecure": true})
			if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err == nil {
				t.Fatal("failed TLS session was accepted")
			}
			if f.sawCommand("MAIL") || f.sawCommand("DATA") {
				t.Fatal("TLS failure downgraded to plaintext mail")
			}
		})
	}
}

func TestEmailInsecureOptInRequiresExplicitStoredSecret(t *testing.T) {
	stored := map[string]any{"host": "smtp.example.test", "port": 587, "password": "synthetic-secret"}
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"allow_insecure": true}); err == nil {
		t.Fatal("plaintext opt-in retained a hidden stored SMTP password")
	}
}
