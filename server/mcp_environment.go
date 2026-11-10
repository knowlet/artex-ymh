package server

import (
	"os"
	"runtime"
	"strings"
)

// norma's stdio constructor only accepts overrides, then appends them to
// os.Environ. Empty overrides remove inherited secret VALUES before exec's
// last-value-wins environment deduplication. Keep runtime essentials, and allow
// the operator to explicitly supply any variables required by this MCP.
// Never mutate the server's process-global environment.
func mcpChildEnv(explicit map[string]string) map[string]string {
	out := make(map[string]string)
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			continue
		}
		out[key] = ""
		switch strings.ToUpper(key) {
		case "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
			"TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
			"XDG_CACHE_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS":
			out[key] = value
		}
	}
	for key, value := range explicit {
		if runtime.GOOS == "windows" {
			for existing := range out {
				if strings.EqualFold(existing, key) {
					delete(out, existing)
				}
			}
		}
		out[key] = value
	}
	return out
}
