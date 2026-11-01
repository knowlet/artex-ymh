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
