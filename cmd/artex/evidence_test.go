package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEvidenceHARAggPrivacy(t *testing.T) {
	const input = `{"log":{"creator":{"name":"SECRET_CREATOR"},"entries":[{"request":{"method":"POST","url":"https://SECRET_URL/?token=SECRET_TOKEN","headers":[{"name":"Authorization","value":"SECRET_AUTH"}],"postData":{"text":"SECRET_BODY"}},"response":{"status":200,"cookies":[{"value":"SECRET_COOKIE"}],"content":{"text":"SECRET_PII"}}},{"request":{"method":"POST"},"response":{"status":200}},{"request":{"method":"SECRET_METHOD"},"response":{"status":0}},{"request":{"method":"GET"},"response":{"status":404}}]}}`
	var out, stderr bytes.Buffer
	if code := runEvidence([]string{"har-summary"}, strings.NewReader(input), &out, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, &stderr)
	}
	const want = `{"mode":"aggregate-metadata-only","entries":4,"counts":[{"method":"GET","status":404,"count":1},{"method":"OTHER","status":0,"count":1},{"method":"POST","status":200,"count":2}]}` + "\n"
	if out.String() != want || stderr.Len() != 0 {
		t.Fatalf("unexpected summary: %q; stderr=%q", out.String(), stderr.String())
	}
}

func TestEvidenceHARRejectsInvalid(t *testing.T) {
	for _, input := range []string{
		`SECRET_INVALID`, `{"log":{"entries":null}}`, `{"log":{"entries":[{}]}}`,
		`{"log":{"entries":[{"request":{"method":"GET"},"response":{"status":999}}]}}`,
		`{"log":{"entries":[{"request":{"method":"GET"},"response":{}}]}}`,
		`{"log":{"entries":[{"request":{"method":"GET"},"response":{"status":"SECRET_TYPE"}}]}}`,
		`{"log":{"entries":[]}} {}`, strings.Repeat("x", maxHARBytes+1),
	} {
		var out, stderr bytes.Buffer
		if code := runEvidence([]string{"har-summary"}, strings.NewReader(input), &out, &stderr); code != 1 || out.Len() != 0 || strings.Contains(stderr.String(), "SECRET") {
			t.Fatalf("unexpected failure: exit=%d output=%q stderr=%q", code, out.String(), stderr.String())
		}
	}
}

func TestEvidenceHAREmptyAndUsage(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := runEvidence([]string{"har-summary"}, strings.NewReader(`{"log":{"entries":[]}}`), &out, &stderr); code != 0 || out.String() != "{\"mode\":\"aggregate-metadata-only\",\"entries\":0,\"counts\":[]}\n" {
		t.Fatalf("empty HAR exit=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := runEvidence([]string{"har-summary", "extra"}, strings.NewReader(""), &out, &stderr); code != 2 || out.Len() != 0 {
		t.Fatalf("invalid usage exit=%d output=%q", code, out.String())
	}
}
