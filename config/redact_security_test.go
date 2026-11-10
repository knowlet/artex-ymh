package config

import (
	"net/url"
	"strings"
	"testing"
)

func TestRedactAmbiguousUserinfoFailsClosed(t *testing.T) {
	for _, scheme := range []string{"postgres", "postgresql"} {
		for _, password := range []string{
			"123/synthetic-secret",
			"123?synthetic-secret",
			"123#synthetic-secret",
			"123/",
			"123?",
			"123#",
			"123@prefix/synthetic-secret",
			"123@synthetic-secret?remainder",
			"123@synthetic-secret#remainder",
			"123@prefix/synthetic-secret?remainder",
			"123@prefix/synthetic-secret#remainder",
		} {
			t.Run(scheme+"/"+password, func(t *testing.T) {
				raw := scheme + "://fixture:" + password + "@db:5432/artex"
				// net/url accepts these strings, but the raw delimiter moved
				// part of the password outside the parsed userinfo.
				if _, err := url.Parse(raw); err != nil {
					t.Fatalf("fixture must parse successfully: %v", err)
				}
				if got := Redact(raw); got != "[redacted PostgreSQL DSN]" {
					t.Fatalf("ambiguous credentials were not fully redacted: %q", got)
				}
			})
		}
	}
}

func TestRedactPreservesUnambiguousConnectionIdentity(t *testing.T) {
	for _, raw := range []string{
		"postgres://fixture:123%2Fsynthetic-secret@db:5432/artex",
		"postgres://fixture:123%3Fsynthetic-secret@db:5432/artex",
		"postgres://fixture:123%23synthetic-secret@db:5432/artex",
		"postgres://fixture:123%40prefix%2Fsynthetic-secret@db:5432/artex",
	} {
		if got, want := Redact(raw), "postgres://fixture:%2A%2A%2A%2A@db:5432/artex"; got != want {
			t.Errorf("Redact(%q) = %q; want %q", raw, got, want)
		}
	}
	for _, raw := range []string{
		"postgres://db:5432/artex",
		"postgresql://fixture@db:5432/artex",
		"postgres://fixture@db:5432/team%40artex",
	} {
		if got := Redact(raw); got != raw {
			t.Errorf("non-secret connection identity changed: %q; want %q", got, raw)
		}
	}
}

func TestRedactEveryDSNFormFailsClosed(t *testing.T) {
	for _, raw := range []string{
		"host=db user=artex password=synthetic-secret dbname=artex",
		"host=db password='synthetic-secret with spaces' user=artex",
		`host=db password='synthetic-secret\'quoted'`,
		"postgres://u:synthetic-secret@db:5432/artex",
		"postgresql://u@db/artex?password=synthetic-secret&sslpassword=synthetic-secret",
		"postgres://u:synthetic-secret%zz@db/artex",
		"postgres://u@db/artex#synthetic-secret",
		"synthetic-secret",
	} {
		got := Redact(raw)
		if strings.Contains(got, "synthetic-secret") {
			t.Fatalf("DSN credential escaped redaction: %q", got)
		}
	}
	got := Redact("postgres://fixture:synthetic-secret@db:5432/artex?sslmode=require")
	if !strings.Contains(got, "fixture") || !strings.Contains(got, "db:5432/artex") {
		t.Fatalf("connection identity lost: %q", got)
	}
}
