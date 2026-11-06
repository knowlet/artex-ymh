package report

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSecurityCSVWhitespaceFormulaPrefixes(t *testing.T) {
	for _, prefix := range []string{"", " ", "\t", "\r\n", "\v\f", "\u00a0", "\uFEFF", " \t\r\n"} {
		for _, formula := range []string{"=1+1", "+1", "-1", "@SUM(1)"} {
			value := prefix + formula
			row := readCSV(t, FindingsCSV([]*db.DBFinding{{
				ID: 1, Name: value, VulnClass: value, Severity: value,
				Status: value, TaskDescription: value, Summary: value,
			}}))[1]
			for _, col := range []int{1, 2, 3, 4, 5, 7} {
				if !strings.HasPrefix(row[col], "'") {
					t.Fatalf("prefix=%q formula=%q column=%d unprotected: %q", prefix, formula, col, row[col])
				}
			}
		}
	}
	for _, text := range []string{"ordinary text", " leading text", "\tindented text", "a=b", "'already text"} {
		if got := csvSafe(text); got != text {
			t.Fatalf("normal cell changed: %q -> %q", text, got)
		}
	}
}
