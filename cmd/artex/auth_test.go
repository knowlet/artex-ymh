package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/xaioauth"
)

type authCLIFixture struct {
	starts, waits, logouts int
	err                    error
}

func (f *authCLIFixture) Start(context.Context) (*xaioauth.DeviceFlow, error) {
	f.starts++
	return &xaioauth.DeviceFlow{DeviceCode: "secret-device-fixture", UserCode: "ABCD-EFGH", VerificationURI: "https://accounts.x.ai/device", ExpiresAt: time.Now().Add(time.Minute), IntervalSeconds: 5}, f.err
}
func (f *authCLIFixture) Wait(context.Context, *xaioauth.DeviceFlow) error { f.waits++; return f.err }
func (f *authCLIFixture) Status() (xaioauth.Status, error) {
	return xaioauth.Status{Connected: true}, f.err
}
func (f *authCLIFixture) Logout(context.Context) error { f.logouts++; return f.err }

func TestXAIAuthCLICommands(t *testing.T) {
	for _, command := range []string{"login", "status", "logout"} {
		t.Run(command, func(t *testing.T) {
			root := t.TempDir()
			fixture := &authCLIFixture{}
			var out, errOut bytes.Buffer
			code := runAuthWithFactory(context.Background(), []string{command, xaioauth.Provider, "--key-dir", root, "--data", filepath.Join(root, "data")}, &out, &errOut, func(path string) subscriptionAuth {
				if path != filepath.Join(root, "xai-oauth", "session.json") {
					t.Errorf("unexpected credential path %q", path)
				}
				return fixture
			})
			if code != 0 || errOut.Len() != 0 {
				t.Fatalf("exit=%d error=%s", code, &errOut)
			}
			if strings.Contains(out.String(), "secret-device-fixture") {
				t.Fatal("device code leaked into CLI output")
			}
			if command == "login" && (fixture.starts != 1 || fixture.waits != 1 || !strings.Contains(out.String(), "https://accounts.x.ai/device") || !strings.Contains(out.String(), "ABCD-EFGH")) {
				t.Fatalf("login not complete: %s", &out)
			}
			if command == "logout" && fixture.logouts != 1 {
				t.Fatal("logout not called")
			}
			if command != "login" {
				if _, err := os.Stat(filepath.Join(root, "xai-oauth")); !os.IsNotExist(err) {
					t.Fatal("read-only or empty logout operation created a credential directory")
				}
			}
		})
	}
}

func TestXAIAuthCLIRejectsInvalidArgumentsBeforeAuth(t *testing.T) {
	for _, args := range [][]string{nil, {"login"}, {"login", "openai"}, {"unknown", xaioauth.Provider}, {"status", xaioauth.Provider, "extra"}} {
		var out bytes.Buffer
		called := false
		code := runAuthWithFactory(context.Background(), args, &out, &out, func(string) subscriptionAuth { called = true; return &authCLIFixture{} })
		if code != 2 || called {
			t.Fatalf("args=%v code=%d auth-called=%v", args, code, called)
		}
	}
}

func TestXAIAuthCLIFailureDoesNotClaimConnected(t *testing.T) {
	root := t.TempDir()
	var out, errOut bytes.Buffer
	fixture := &authCLIFixture{err: errors.New("access denied")}
	code := runAuthWithFactory(context.Background(), []string{"login", xaioauth.Provider, "--key-dir", root}, &out, &errOut, func(string) subscriptionAuth { return fixture })
	if code != 1 || strings.Contains(out.String(), "connected") || fixture.waits != 0 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, &out, &errOut)
	}
}

func TestXAIAuthCLIProtectsPrivateLocation(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := subscriptionStorePath(data, data, true); err == nil {
		t.Fatal("accepted browsable credential location")
	}
	if _, err := subscriptionStorePath(root, filepath.Join(root, "xai-oauth"), true); err == nil {
		t.Fatal("accepted a credential subdirectory overlapping the custom data directory")
	}
	if runtime.GOOS == "windows" {
		return
	}
	private := filepath.Join(root, "xai-oauth")
	if err := os.Symlink(data, private); err != nil {
		t.Fatal(err)
	}
	if _, err := subscriptionStorePath(root, data, true); err == nil {
		t.Fatal("accepted symlink credential directory")
	}
	if err := os.Remove(private); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(private, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := subscriptionStorePath(root, data, true); err == nil {
		t.Fatal("accepted shared credential directory")
	}
}

func TestXAIAuthCLIRejectsWorkspaceAliasesBeforeAuthOrMutation(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, command := range []string{"login", "status", "logout"} {
			name := "missing_child_under_alias/" + command
			if existing {
				name = "existing_workspace_alias/" + command
			}
			t.Run(name, func(t *testing.T) {
				keyDir := t.TempDir()
				privateDir := filepath.Join(keyDir, "xai-oauth")
				const fixture = "existing-credential-fixture-must-not-be-read-or-modified"
				if existing {
					if err := os.Mkdir(privateDir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(privateDir, "session.json"), []byte(fixture), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				alias := filepath.Join(t.TempDir(), "workspace-alias")
				target := keyDir
				if existing {
					target = privateDir
				}
				if err := os.Symlink(target, alias); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink unavailable: %v", err)
					}
					t.Fatal(err)
				}
				dataDir := alias
				if !existing {
					dataDir = filepath.Join(alias, "xai-oauth")
				}
				called := false
				var out, errOut bytes.Buffer
				code := runAuthWithFactory(t.Context(), []string{command, xaioauth.Provider, "--key-dir", keyDir, "--data", dataDir}, &out, &errOut,
					func(string) subscriptionAuth { called = true; return &authCLIFixture{} })
				if code != 1 || called || out.Len() != 0 || !strings.Contains(errOut.String(), "outside the browsable data directory") {
					t.Fatalf("unsafe alias reached auth: code=%d factory=%t stdout=%s stderr=%s", code, called, &out, &errOut)
				}
				if _, err := os.Lstat(filepath.Join(privateDir, "session.json.lock")); !os.IsNotExist(err) {
					t.Fatalf("unsafe store lock was created: %v", err)
				}
				if existing {
					body, err := os.ReadFile(filepath.Join(privateDir, "session.json"))
					if err != nil || string(body) != fixture {
						t.Fatalf("existing credential was modified: %v", err)
					}
					entries, err := os.ReadDir(privateDir)
					if err != nil || len(entries) != 1 || entries[0].Name() != "session.json" {
						t.Fatalf("unsafe directory was mutated: %v %v", entries, err)
					}
				} else if _, err := os.Lstat(privateDir); !os.IsNotExist(err) {
					t.Fatalf("unsafe credential directory was created: %v", err)
				}
			})
		}
	}
}

func TestXAIAuthCLIAcceptsSafeSiblingWithoutStatusMutation(t *testing.T) {
	keyDir := t.TempDir()
	dataDir := filepath.Join(keyDir, "xai-oauth-public", "data")
	called := false
	var out, errOut bytes.Buffer
	code := runAuthWithFactory(t.Context(), []string{"status", xaioauth.Provider, "--key-dir", keyDir, "--data", dataDir}, &out, &errOut,
		func(path string) subscriptionAuth {
			called = true
			if path != filepath.Join(keyDir, "xai-oauth", "session.json") {
				t.Errorf("unexpected safe path: %s", path)
			}
			return &authCLIFixture{}
		})
	if code != 0 || !called || errOut.Len() != 0 {
		t.Fatalf("safe sibling rejected: code=%d factory=%t error=%s", code, called, &errOut)
	}
	entries, err := os.ReadDir(keyDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("safe status check mutated storage: %v %v", entries, err)
	}
}
