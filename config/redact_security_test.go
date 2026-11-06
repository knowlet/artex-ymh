package config

import (
	"strings"
	"testing"
)

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
