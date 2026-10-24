// Package discovery builds bounded, reviewable ProjectDiscovery command plans.
// It does not discover authorization or provide an operating-system egress policy.
package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ProfileLowNoise = "low-noise"
	ProfileStandard = "standard"
	ProfilePassive  = "passive"
	DefaultTimeout  = 2 * time.Minute
	MaxTimeout      = time.Hour
)

// Options deliberately has no arbitrary flags, shell fragment, target list,
// custom configuration, or remote template input.
type Options struct {
	Tool         string
	Target       string
	Profile      string
	ToolsDir     string
	TemplatesDir string
	Templates    []string
	Timeout      time.Duration
}

// Plan is a dry-run description. Run rebuilds it from Options; editing this
// description cannot inject executable arguments into a later Run.
type Plan struct {
	Tool           string            `json:"tool"`
	Target         string            `json:"target"`
	Profile        string            `json:"profile"`
	Binary         string            `json:"binary"`
	Args           []string          `json:"args"`
	TimeoutSeconds float64           `json:"timeout_seconds"`
	RateLimit      int               `json:"rate_limit"`
	Concurrency    int               `json:"concurrency"`
	TemplateSHA256 map[string]string `json:"template_sha256,omitempty"`
	Caveats        []string          `json:"caveats"`
}

// BuildPlan validates all local inputs without starting a process or accessing
// a network. Tools must be installed explicitly under an absolute ToolsDir.
func BuildPlan(opts Options) (*Plan, error) {
	if opts.Profile == "" {
		opts.Profile = ProfileLowNoise
	}
	rate, concurrency := 1, 1
	switch opts.Profile {
	case ProfileLowNoise, ProfilePassive:
	case ProfileStandard:
		rate, concurrency = 5, 2
	default:
		return nil, fmt.Errorf("unknown discovery profile %q", opts.Profile)
	}
	switch opts.Tool {
	case "httpx", "katana", "nuclei", "naabu", "subfinder":
	default:
		return nil, fmt.Errorf("unsupported discovery tool %q", opts.Tool)
	}
	if opts.Profile == ProfilePassive && opts.Tool != "subfinder" {
		return nil, fmt.Errorf("passive profile supports subfinder only")
	}
	if opts.Tool != "nuclei" && (opts.TemplatesDir != "" || len(opts.Templates) != 0) {
		return nil, fmt.Errorf("template options require nuclei")
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Timeout <= 0 || opts.Timeout > MaxTimeout {
		return nil, fmt.Errorf("discovery timeout must be greater than zero and at most %s", MaxTimeout)
	}
	toolsDir, err := absoluteDirectory(opts.ToolsDir, "tools directory")
	if err != nil {
		return nil, err
	}
	binary, err := containedFile(toolsDir, opts.Tool)
	if err != nil {
		return nil, fmt.Errorf("discovery tool %s: %w", opts.Tool, err)
	}
	info, err := os.Stat(binary)
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("discovery tool %s is not executable", opts.Tool)
	}
	plan := &Plan{
		Tool: opts.Tool, Profile: opts.Profile, Binary: binary,
		TimeoutSeconds: opts.Timeout.Seconds(), RateLimit: rate, Concurrency: concurrency,
		Caveats: []string{
			"Rate and concurrency limits apply to this subprocess, not other workers or arbitrary Bash commands.",
			"Low-noise limits request volume; it does not guarantee invisibility or enforce network egress scope.",
			"The subprocess runs with isolated configuration and without inherited provider credentials; configured proxy and TLS trust variables are retained.",
		},
	}
	r, c := strconv.Itoa(rate), strconv.Itoa(concurrency)
	switch opts.Tool {
	case "httpx", "katana", "nuclei":
		u, err := targetURL(opts.Target)
		if err != nil {
			return nil, err
		}
		plan.Target = u.String()
		switch opts.Tool {
		case "httpx":
			plan.Args = []string{"-u", plan.Target, "-json", "-silent", "-no-color", "-duc", "-no-stdin", "-nfs", "-random-agent=false", "-follow-redirects=false", "-follow-host-redirects=false", "-rl", r, "-threads", c, "-timeout", "10", "-retries", "0"}
		case "katana":
			// Escape the entire authority, anchor its end, and keep the input
			// scheme/port. A regex for just example.com also matches evil hosts.
			scope := "^" + regexp.QuoteMeta(u.Scheme+"://"+u.Host) + "(?:[/?#]|$)"
			depth := "1"
			if opts.Profile == ProfileStandard {
				depth = "2"
			}
			plan.Args = []string{"-u", plan.Target, "-jsonl", "-silent", "-no-color", "-duc", "-dr", "-fs", "fqdn", "-cs", scope, "-d", depth, "-c", c, "-p", "1", "-rl", r, "-timeout", "10", "-retry", "0", "-iqp"}
			plan.Caveats = append(plan.Caveats, "Crawling uses one exact origin and depth 1 (low-noise) or 2 (standard); discovered URLs do not expand authorization.")
		case "nuclei":
			templates, hashes, err := templateFiles(opts.TemplatesDir, opts.Templates)
			if err != nil {
				return nil, err
			}
			plan.TemplateSHA256 = hashes
			plan.Args = []string{"-u", plan.Target, "-jsonl", "-silent", "-no-color", "-duc", "-no-stdin", "-nh", "-ni", "-dut", "-dr", "-pt", "http", "-etags", "intrusive,code,headless,dos,fuzz,fuzzing,bruteforce,token-spray,creds-stuffing", "-rl", r, "-c", c, "-bs", "1", "-pc", "1", "-prc", "1", "-timeout", "10", "-retries", "0"}
			for _, file := range templates {
				plan.Args = append(plan.Args, "-t", file)
			}
			plan.Caveats = append(plan.Caveats, "Only explicitly selected local template files are passed; SHA-256 records content, not upstream authenticity. Review templates and their embedded requests; protocol/tag filters are not a network firewall.")
		}
	case "naabu", "subfinder":
		host, err := targetHost(opts.Target)
		if err != nil {
			return nil, err
		}
		plan.Target = host
		if opts.Tool == "naabu" {
			// An explicit short port set avoids tool-specific top-port aliases
			// expanding to hundreds of ports when a version changes.
			// Naabu v2.6.1 uses goflags.DurationVar: its unitless values are
			// seconds, despite the help text claiming milliseconds. Always
			// include a unit (goflags v0.1.74 duration_var.go).
			plan.Args = []string{"-host", host, "-json", "-silent", "-no-color", "-duc", "-no-stdin", "-s", "c", "-Pn", "-p", "80,443,8080,8443", "-rate", r, "-c", c, "-retries", "1", "-timeout", "1s"}
		} else {
			if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
				return nil, fmt.Errorf("subfinder requires a DNS domain, not an IP or single-label host")
			}
			plan.Args = []string{"-d", host, "-json", "-silent", "-no-color", "-duc", "-rl", r, "-t", c, "-timeout", "10"}
			plan.Caveats = append(plan.Caveats, "Subfinder queries third-party passive providers and does not use active DNS validation; findings are candidates, not permission to probe them.")
		}
	}
	return plan, nil
}

// Run revalidates Options, streams JSONL to stdout and diagnostics to stderr,
// and kills the tool when the caller cancels or the wall-clock timeout expires.
// Partial output may exist on any error and must not be treated as a clean scan.
func Run(ctx context.Context, opts Options, stdout, stderr io.Writer) error {
	plan, err := BuildPlan(opts)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.TimeoutSeconds*float64(time.Second)))
	defer cancel()
	configDir, err := os.MkdirTemp("", "artex-discovery-")
	if err != nil {
		return fmt.Errorf("create isolated tool configuration: %w", err)
	}
	defer os.RemoveAll(configDir)
	configDir, err = filepath.EvalSymlinks(configDir)
	if err != nil {
		return fmt.Errorf("resolve isolated tool configuration: %w", err)
	}
	cmd := exec.CommandContext(runCtx, plan.Binary, plan.Args...)
	cmd.Dir = configDir
	cmd.Env = isolatedEnvironment(configDir)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if runCtx.Err() != nil {
			return fmt.Errorf("%s stopped; output may be incomplete: %w", opts.Tool, runCtx.Err())
		}
		return fmt.Errorf("%s failed; output may be incomplete: %w", opts.Tool, err)
	}
	return nil
}

func absoluteDirectory(path, label string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute path", label)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", label, err)
	}
	info, err := os.Stat(real)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", label)
	}
	return real, nil
}

func containedFile(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || strings.ContainsAny(relative, "\x00\r\n,") {
		return "", fmt.Errorf("file must be an explicit relative path")
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, relative))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("file escapes its configured directory")
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("file is not a regular file")
	}
	return real, nil
}

func templateFiles(root string, selected []string) ([]string, map[string]string, error) {
	if len(selected) == 0 || len(selected) > 64 {
		return nil, nil, fmt.Errorf("nuclei requires 1 to 64 explicitly selected template files")
	}
	dir, err := absoluteDirectory(root, "templates directory")
	if err != nil {
		return nil, nil, err
	}
	if strings.ContainsAny(dir, "\x00\r\n,") {
		return nil, nil, fmt.Errorf("templates directory cannot contain control characters or commas")
	}
	files, hashes := make([]string, 0, len(selected)), make(map[string]string, len(selected))
	seen := make(map[string]bool, len(selected))
	for _, name := range selected {
		if ext := filepath.Ext(name); ext != ".yaml" && ext != ".yml" {
			return nil, nil, fmt.Errorf("template %q must be a YAML file", name)
		}
		file, err := containedFile(dir, name)
		if err != nil {
			return nil, nil, fmt.Errorf("template %q: %w", name, err)
		}
		if seen[file] {
			return nil, nil, fmt.Errorf("duplicate template %q", name)
		}
		seen[file] = true
		f, err := os.Open(file)
		if err != nil {
			return nil, nil, err
		}
		h := sha256.New()
		n, readErr := io.Copy(h, io.LimitReader(f, 8<<20+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || n > 8<<20 {
			return nil, nil, fmt.Errorf("template %q cannot be read or exceeds 8 MiB", name)
		}
		files = append(files, file)
		hashes[name] = hex.EncodeToString(h.Sum(nil))
	}
	return files, hashes, nil
}

func targetURL(target string) (*url.URL, error) {
	if target == "" || strings.ContainsAny(target, "\x00\r\n\t ,\\") || strings.TrimSpace(target) != target {
		return nil, fmt.Errorf("target must be one HTTP(S) URL without whitespace or comma-separated inputs")
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("target must be one absolute HTTP(S) URL without credentials or fragment")
	}
	if _, err := targetHost(u.Hostname()); err != nil {
		return nil, err
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("target port cannot be empty")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("target port must be between 1 and 65535")
		}
	}
	return u, nil
}

func targetHost(target string) (string, error) {
	if target == "" || len(target) > 253 || strings.TrimSpace(target) != target {
		return "", fmt.Errorf("target must be one hostname or IP address")
	}
	if ip := net.ParseIP(target); ip != nil {
		return ip.String(), nil
	}
	host := strings.ToLower(strings.TrimSuffix(target, "."))
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid target hostname %q", target)
		}
		for _, ch := range label {
			if ch != '-' && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') {
				return "", fmt.Errorf("invalid target hostname %q", target)
			}
		}
	}
	return host, nil
}

func isolatedEnvironment(dir string) []string {
	allowed := map[string]bool{
		"PATH": true, "SYSTEMROOT": true, "TMPDIR": true, "LANG": true, "LC_ALL": true,
		"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "NO_PROXY": true,
		"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true,
	}
	env := []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "config")}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if allowed[key] {
			env = append(env, entry)
		}
	}
	return env
}
