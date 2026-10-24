package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A copied test executable acts as a real subprocess without invoking a shell,
// installing scanners, or accessing a network.
func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "httpx", "katana", "nuclei", "naabu", "subfinder":
		mode, _ := os.ReadFile(filepath.Join(filepath.Dir(os.Args[0]), "stub-mode"))
		switch string(mode) {
		case "wait":
			for {
				time.Sleep(10 * time.Millisecond)
			}
		case "fail":
			os.Stderr.WriteString("stub failed\n")
			os.Exit(7)
		}
		cwd, _ := os.Getwd()
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"args": os.Args[1:], "home": os.Getenv("HOME"),
			"config": os.Getenv("XDG_CONFIG_HOME"), "cwd": cwd,
			"provider_key":    os.Getenv("PDCP_API_KEY"),
			"injected_config": os.Getenv("SUBFINDER_CONFIG"),
			"https_proxy":     os.Getenv("HTTPS_PROXY"),
		})
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func stubTools(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		in, err := os.Open(exe)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
		if err != nil {
			in.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(out, in)
		in.Close()
		closeErr := out.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatalf("copy helper: %v, %v", copyErr, closeErr)
		}
	}
	return dir
}

func TestBoundedPlans(t *testing.T) {
	dir := stubTools(t, "httpx", "katana", "naabu", "subfinder", "nuclei")
	templates := t.TempDir()
	if err := os.WriteFile(filepath.Join(templates, "test.yaml"), []byte("id: fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"httpx", "katana", "naabu", "subfinder", "nuclei"} {
		for _, profile := range []string{ProfileLowNoise, ProfileStandard} {
			t.Run(tool+"/"+profile, func(t *testing.T) {
				opts := Options{Tool: tool, Target: "example.com", ToolsDir: dir, Profile: profile}
				if tool == "httpx" || tool == "katana" || tool == "nuclei" {
					opts.Target = "https://example.com:8443/start"
				}
				if tool == "nuclei" {
					opts.TemplatesDir, opts.Templates = templates, []string{"test.yaml"}
				}
				plan, err := BuildPlan(opts)
				if err != nil {
					t.Fatal(err)
				}
				wantRate, wantConcurrency := 1, 1
				if profile == ProfileStandard {
					wantRate, wantConcurrency = 5, 2
				}
				if plan.RateLimit != wantRate || plan.Concurrency != wantConcurrency || plan.TimeoutSeconds != 120 {
					t.Fatalf("unbounded profile: %+v", plan)
				}
				if !containsArg(plan.Args, "-duc") || !containsArg(plan.Args, "-silent") {
					t.Fatalf("missing fixed controls: %v", plan.Args)
				}
				if tool == "nuclei" {
					for _, flag := range []string{"-dut", "-ni", "-dr", "-nh"} {
						if !containsArg(plan.Args, flag) {
							t.Fatalf("missing nuclei control %s", flag)
						}
					}
					if got := plan.TemplateSHA256["test.yaml"]; len(got) != 64 {
						t.Fatalf("missing template digest: %v", plan.TemplateSHA256)
					}
				}
				if tool == "naabu" && (!containsArg(plan.Args, "80,443,8080,8443") || !containsArg(plan.Args, "-Pn")) {
					t.Fatalf("naabu scope too broad: %v", plan.Args)
				}
			})
		}
	}
}

func TestKatanaExactOriginScope(t *testing.T) {
	dir := stubTools(t, "katana")
	for _, target := range []string{"https://example.com:8443/path", "http://[::1]:8080/"} {
		plan, err := BuildPlan(Options{Tool: "katana", Target: target, ToolsDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		var scope string
		for i, arg := range plan.Args {
			if arg == "-cs" {
				scope = plan.Args[i+1]
			}
		}
		re := regexp.MustCompile(scope)
		if !re.MatchString(target) || re.MatchString("https://example.com.evil.test:8443/path") || re.MatchString("https://exampleXcom:8443/") || re.MatchString("https://example.com:443/") || re.MatchString("http://example.com:8443/") {
			t.Fatalf("scope does not constrain exact origin: %s", scope)
		}
		if !containsArg(plan.Args, "fqdn") || !containsArg(plan.Args, "-dr") {
			t.Fatalf("missing crawl boundary: %v", plan.Args)
		}
	}
}

func TestTimeoutArgumentUnits(t *testing.T) {
	dir := stubTools(t, "httpx", "katana", "naabu", "subfinder", "nuclei")
	templates := t.TempDir()
	if err := os.WriteFile(filepath.Join(templates, "test.yaml"), []byte("id: fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for tool, want := range map[string]string{"httpx": "10", "katana": "10", "nuclei": "10", "subfinder": "10", "naabu": "1s"} {
		t.Run(tool, func(t *testing.T) {
			opts := Options{Tool: tool, Target: "example.com", ToolsDir: dir}
			if tool == "httpx" || tool == "katana" || tool == "nuclei" {
				opts.Target = "https://example.com/"
			}
			if tool == "nuclei" {
				opts.TemplatesDir, opts.Templates = templates, []string{"test.yaml"}
			}
			plan, err := BuildPlan(opts)
			if err != nil {
				t.Fatal(err)
			}
			for i, arg := range plan.Args {
				if arg == "-timeout" {
					if got := plan.Args[i+1]; got != want {
						t.Fatalf("%s timeout=%q want %q; Naabu uses a duration, other tools use integer seconds", tool, got, want)
					}
					return
				}
			}
			t.Fatal("missing request timeout")
		})
	}
}

func TestRejectInvalidInputs(t *testing.T) {
	dir := stubTools(t, "httpx", "subfinder", "nuclei", "naabu")
	base := Options{Tool: "httpx", Target: "https://example.com/", ToolsDir: dir}
	cases := []struct {
		name string
		edit func(*Options)
	}{
		{"unknown tool", func(o *Options) { o.Tool = "sh" }},
		{"tool path injection", func(o *Options) { o.Tool = "../httpx" }},
		{"unknown profile", func(o *Options) { o.Profile = "deep" }},
		{"active passive tool", func(o *Options) { o.Profile = ProfilePassive }},
		{"relative tools", func(o *Options) { o.ToolsDir = "." }},
		{"missing tools", func(o *Options) { o.ToolsDir = filepath.Join(dir, "missing") }},
		{"negative timeout", func(o *Options) { o.Timeout = -time.Second }},
		{"huge timeout", func(o *Options) { o.Timeout = MaxTimeout + time.Second }},
		{"url list", func(o *Options) { o.Target = "https://a.test/,https://b.test/" }},
		{"newline", func(o *Options) { o.Target = "https://a.test/\n-t /tmp" }},
		{"non-http", func(o *Options) { o.Target = "file:///etc/passwd" }},
		{"userinfo", func(o *Options) { o.Target = "https://me:secret@example.com/" }},
		{"fragment", func(o *Options) { o.Target = "https://example.com/#x" }},
		{"bad port", func(o *Options) { o.Target = "https://example.com:65536/" }},
		{"host wildcard", func(o *Options) { o.Target = "https://*.example.com/" }},
		{"no scheme", func(o *Options) { o.Target = "example.com" }},
		{"host flags", func(o *Options) { o.Tool, o.Target = "naabu", "-host" }},
		{"host list", func(o *Options) { o.Tool, o.Target = "naabu", "example.com,a.test" }},
		{"network range", func(o *Options) { o.Tool, o.Target = "naabu", "192.0.2.0/24" }},
		{"domain IP", func(o *Options) { o.Tool, o.Target = "subfinder", "192.0.2.1" }},
		{"no selected templates", func(o *Options) { o.Tool = "nuclei" }},
		{"unrelated template options", func(o *Options) { o.Templates = []string{"x.yaml"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.edit(&opts)
			if plan, err := BuildPlan(opts); err == nil {
				t.Fatalf("accepted invalid input: %+v", plan)
			}
		})
	}
}

func TestTemplateBoundaries(t *testing.T) {
	dir := stubTools(t, "nuclei")
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(external, []byte("id: external\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "escape.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok.yaml"), []byte("id: okay\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, selected := range [][]string{{"../outside.yaml"}, {external}, {"escape.yaml"}, {"directory.yaml"}, {"http/"}, {"https://example.com/t.yaml"}, {"ok.yaml", "ok.yaml"}, {"ok.yaml,other.yaml"}} {
		if plan, err := BuildPlan(Options{Tool: "nuclei", Target: "https://example.com/", ToolsDir: dir, TemplatesDir: root, Templates: selected}); err == nil {
			t.Fatalf("accepted unsafe template selection %q: %+v", selected, plan)
		}
	}
}

func TestRejectToolSymlinkEscapeAndNonExecutable(t *testing.T) {
	dir := t.TempDir()
	outside := stubTools(t, "httpx")
	if err := os.Symlink(filepath.Join(outside, "httpx"), filepath.Join(dir, "httpx")); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(Options{Tool: "httpx", Target: "https://example.com/", ToolsDir: dir}); err == nil {
		t.Fatal("accepted executable outside tool directory")
	}
	if err := os.WriteFile(filepath.Join(dir, "katana"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(Options{Tool: "katana", Target: "https://example.com/", ToolsDir: dir}); err == nil {
		t.Fatal("accepted non-executable tool")
	}
}

func TestPassiveAndLiteralIPv6(t *testing.T) {
	dir := stubTools(t, "subfinder", "naabu")
	p, err := BuildPlan(Options{Tool: "subfinder", Target: "Example.COM.", ToolsDir: dir, Profile: ProfilePassive})
	if err != nil {
		t.Fatal(err)
	}
	if p.Target != "example.com" || containsArg(p.Args, "-active") {
		t.Fatalf("passive plan changed: %+v", p)
	}
	if _, err := BuildPlan(Options{Tool: "naabu", Target: "2001:db8::1", ToolsDir: dir}); err != nil {
		t.Fatal(err)
	}
}

func TestRunStreamsLiteralArgvAndIsolatesConfiguration(t *testing.T) {
	dir := stubTools(t, "httpx")
	t.Setenv("PDCP_API_KEY", "must-not-inherit")
	t.Setenv("SUBFINDER_CONFIG", "/untrusted/config.yaml")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1234")
	// These characters would be shell syntax if a shell were used. They must
	// reach the executable as one URL argument without executing anything.
	target := "https://example.com/?value=$(touch%20DO_NOT_CREATE);echo"
	opts := Options{Tool: "httpx", Target: target, ToolsDir: dir}
	plan, err := BuildPlan(opts)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), opts, &stdout, &stderr); err != nil {
		t.Fatalf("Run: %v, stderr: %s", err, &stderr)
	}
	var got struct {
		Args           []string `json:"args"`
		Home           string   `json:"home"`
		Config         string   `json:"config"`
		CWD            string   `json:"cwd"`
		ProviderKey    string   `json:"provider_key"`
		InjectedConfig string   `json:"injected_config"`
		Proxy          string   `json:"https_proxy"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Args, plan.Args) || got.Args[1] != target {
		t.Fatalf("argv changed: %+v", got)
	}
	if got.Home == "" || got.Config != filepath.Join(got.Home, "config") || got.CWD != got.Home || got.ProviderKey != "" || got.InjectedConfig != "" || got.Proxy != "http://127.0.0.1:1234" {
		t.Fatalf("configuration was not isolated: %+v", got)
	}
	if _, err := os.Stat(got.Home); !os.IsNotExist(err) {
		t.Fatalf("temporary tool config was not removed: %v", err)
	}
}

func TestRunCancellationTimeoutAndFailure(t *testing.T) {
	dir := stubTools(t, "httpx")
	if err := os.WriteFile(filepath.Join(dir, "stub-mode"), []byte("wait"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{Tool: "httpx", Target: "https://example.com/", ToolsDir: dir, Timeout: 40 * time.Millisecond}
	if err := Run(t.Context(), opts, io.Discard, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout did not propagate: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	opts.Timeout = time.Minute
	if err := Run(ctx, opts, io.Discard, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation did not propagate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stub-mode"), []byte("fail"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := Run(t.Context(), opts, io.Discard, &stderr); err == nil || !strings.Contains(err.Error(), "incomplete") || !strings.Contains(stderr.String(), "stub failed") {
		t.Fatalf("failed process claimed completion: err=%v stderr=%s", err, &stderr)
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
