package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/endpoint"
)

var errMCPNotFound = errors.New("MCP 服务器不存在")

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
		return errMCPNotFound
	}
	if strings.EqualFold(strings.TrimSpace(cur.Transport), "stdio") {
		if strings.TrimSpace(m.Command) == "" {
			m.Command = cur.Command
		}
		if mcpFieldUnset(m.Args) {
			m.Args = cur.Args
		}
	}

	url := strings.TrimSpace(m.URL)
	if url == "" {
		url = cur.URL
	}
	destChanged := mcpDestinationChanged(cur, m, url)
	storedSecrets := mcpStoredSecretKeys(cur.Env)

	if destChanged && len(storedSecrets) > 0 {
		if err := mcpRequireSecretReentry(cur.Env, m.Env); err != nil {
			return err
		}
	}

	keepSecrets := len(storedSecrets) > 0 && !destChanged
	if strings.TrimSpace(m.URL) != "" {
		resolved, err := resolveCredentialEndpoint(cur.URL, url, keepSecrets)
		if err != nil {
			return err
		}
		url = resolved
	}

	if destChanged {
		m.Insecure = false
	}
	m.URL = url

	if !destChanged && keepSecrets {
		m.Env = mcpMergeEnv(cur.Env, m.Env)
	}
	return nil
}

func mcpDestinationChanged(cur, incoming *db.MCPServer, resolvedURL string) bool {
	if strings.TrimSpace(cur.Transport) != strings.TrimSpace(incoming.Transport) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(cur.Transport), "stdio") {
		if strings.TrimSpace(cur.Command) != strings.TrimSpace(incoming.Command) {
			return true
		}
		if mcpStdioArgsChanged(cur.Args, incoming.Args) {
			return true
		}
	}
	return mcpEndpointChanged(cur.URL, resolvedURL)
}

func mcpStdioArgsChanged(before, after json.RawMessage) bool {
	if mcpFieldUnset(after) {
		return false
	}
	var have, want []string
	before = bytes.TrimSpace(before)
	after = bytes.TrimSpace(after)
	if err := json.Unmarshal(before, &have); err != nil {
		return !bytes.Equal(before, after)
	}
	if err := json.Unmarshal(after, &want); err != nil {
		return true
	}
	if len(have) != len(want) {
		return true
	}
	for i := range have {
		if have[i] != want[i] {
			return true
		}
	}
	return false
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

func mcpStoredSecretKeys(raw json.RawMessage) []string {
	var keys []string
	for key, val := range jsonStrMap(raw) {
		if strings.TrimSpace(val) != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func mcpRequireSecretReentry(before, after json.RawMessage) error {
	old := jsonStrMap(before)
	new := jsonStrMap(after)
	for key, ov := range old {
		ov = strings.TrimSpace(ov)
		if ov == "" {
			continue
		}
		nv := strings.TrimSpace(new[key])
		if nv == "" || nv == ov {
			return endpoint.ErrCredentialDestination
		}
	}
	return nil
}

func mcpMergeEnv(stored, incoming json.RawMessage) json.RawMessage {
	if len(incoming) == 0 || bytes.Equal(bytes.TrimSpace(incoming), []byte("{}")) {
		return stored
	}
	old := jsonStrMap(stored)
	neu := jsonStrMap(incoming)
	if neu == nil {
		neu = map[string]string{}
	}
	for key, val := range old {
		if _, ok := neu[key]; !ok {
			neu[key] = val
		}
	}
	b, err := json.Marshal(neu)
	if err != nil {
		return stored
	}
	return b
}

func mcpNotFoundMessage(err error) bool {
	return errors.Is(err, errMCPNotFound)
}

func mcpFieldUnset(raw json.RawMessage) bool {
	b := bytes.TrimSpace(raw)
	return len(b) == 0 || bytes.Equal(b, []byte("null"))
}

// mcpEnvSetAPIKey replaces any case variant of X-API-Key with one canonical entry.
func mcpEnvSetAPIKey(raw json.RawMessage, apiKey string) (json.RawMessage, error) {
	env := jsonStrMap(raw)
	if env == nil {
		env = map[string]string{}
	}
	for key := range env {
		if strings.EqualFold(key, "X-API-Key") {
			delete(env, key)
		}
	}
	env["X-API-Key"] = apiKey
	return json.Marshal(env)
}
