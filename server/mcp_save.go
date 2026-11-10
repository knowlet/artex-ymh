package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/endpoint"
)

// prepareMCPSave applies credential-destination and TLS opt-in rules before persisting.
func prepareMCPSave(pg *db.DB, m *db.MCPServer) error {
	if m == nil || m.ID == 0 {
		return nil
	}
	servers, err := pg.ListMCP()
	if err != nil {
		return err
	}
	var cur *db.MCPServer
	for _, row := range servers {
		if row.ID == m.ID {
			cur = row
			break
		}
	}
	if cur == nil {
		return fmt.Errorf("MCP 服务器不存在")
	}
	keepSecret := envHasValue(cur.Env) && !mcpEnvProvidesNewSecrets(cur.Env, m.Env)
	url := strings.TrimSpace(m.URL)
	if url == "" {
		url = cur.URL
	} else {
		resolved, err := resolveCredentialEndpoint(cur.URL, url, keepSecret)
		if err != nil {
			return err
		}
		url = resolved
	}
	if changed := mcpEndpointChanged(cur.URL, url); changed {
		m.Insecure = false
	}
	m.URL = url
	if keepSecret && !mcpEnvProvidesNewSecrets(cur.Env, m.Env) {
		m.Env = cur.Env
	}
	return nil
}

func mcpEndpointChanged(before, after string) bool {
	if strings.TrimSpace(before) == "" || strings.TrimSpace(after) == "" {
		return false
	}
	a, errA := endpoint.URL(before)
	b, errB := endpoint.URL(after)
	if errA != nil || errB != nil {
		return before != after
	}
	return a != b
}

func mcpEnvProvidesNewSecrets(before, after json.RawMessage) bool {
	if len(after) == 0 || bytes.Equal(bytes.TrimSpace(after), []byte("{}")) {
		return false
	}
	old := jsonStrMap(before)
	for key, val := range jsonStrMap(after) {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if val != strings.TrimSpace(old[key]) {
			return true
		}
	}
	return false
}
