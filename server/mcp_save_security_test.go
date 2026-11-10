package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/endpoint"
)

func uniqueMCPName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
}

func TestMCPRequireSecretReentry(t *testing.T) {
	old, _ := json.Marshal(map[string]string{"Authorization": "old-token"})
	if err := mcpRequireSecretReentry(old, old); err == nil {
		t.Fatal("unchanged env must not pass reentry")
	}
	neu, _ := json.Marshal(map[string]string{"Authorization": "old-token", "X-Extra": "1"})
	if err := mcpRequireSecretReentry(old, neu); err == nil {
		t.Fatal("adding headers must not substitute for rotating stored secrets")
	}
	replaced, _ := json.Marshal(map[string]string{"Authorization": "new-token", "X-Extra": "1"})
	if err := mcpRequireSecretReentry(old, replaced); err != nil {
		t.Fatal(err)
	}
}

func TestMCPMergeEnvToleratesNullJSON(t *testing.T) {
	stored := json.RawMessage(`{"X-API-Key":"synthetic-old"}`)
	got := mcpMergeEnv(stored, json.RawMessage(`null`))
	var env map[string]string
	if err := json.Unmarshal(got, &env); err != nil {
		t.Fatal(err)
	}
	if env["X-API-Key"] != "synthetic-old" {
		t.Fatalf("stored secret not preserved: %#v", env)
	}
}

func testManagerPG(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func TestPrepareMCPSaveClearsInsecureOnURLChange(t *testing.T) {
	m := testManagerPG(t)
	pg := m.pg
	name := uniqueMCPName(t)
	id, err := pg.SaveMCP(&db.MCPServer{
		Name: name, Transport: "http", URL: "http://127.0.0.1:8080/mcp",
		Enabled: true, Insecure: true,
		Env: json.RawMessage(`{"X-API-Key":"synthetic-old"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteMCP(id) })
	incoming := &db.MCPServer{
		ID: id, Name: name, Transport: "http",
		URL: "http://127.0.0.1:8081/mcp", Insecure: true, Enabled: true,
		Env: json.RawMessage(`{"X-API-Key":"synthetic-new"}`),
	}
	if err := prepareMCPSave(pg, incoming); err != nil {
		t.Fatal(err)
	}
	if incoming.Insecure {
		t.Fatal("insecure TLS opt-in must reset when the URL changes")
	}
}

func TestPrepareMCPSaveRejectsCommandSwapWithStoredEnv(t *testing.T) {
	m := testManagerPG(t)
	pg := m.pg
	name := uniqueMCPName(t)
	id, err := pg.SaveMCP(&db.MCPServer{
		Name: name, Transport: "stdio", Command: "fixture-old",
		Args: json.RawMessage(`["--fixture"]`),
		Enabled: true, Env: json.RawMessage(`{"API_KEY":"synthetic-old"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteMCP(id) })
	incoming := &db.MCPServer{
		ID: id, Name: name, Transport: "stdio", Command: "fixture-attacker",
		Enabled: true, Env: json.RawMessage(`{}`),
	}
	if err := prepareMCPSave(pg, incoming); !errors.Is(err, endpoint.ErrCredentialDestination) {
		t.Fatalf("command swap with retained secrets: %v", err)
	}
}

func TestPrepareMCPSavePreservesStdioArgsWhenOmitted(t *testing.T) {
	m := testManagerPG(t)
	pg := m.pg
	name := uniqueMCPName(t)
	id, err := pg.SaveMCP(&db.MCPServer{
		Name: name, Transport: "stdio", Command: "fixture-cmd",
		Args: json.RawMessage(`["--sandbox"]`),
		Enabled: true, Env: json.RawMessage(`{"API_KEY":"synthetic-old"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteMCP(id) })
	incoming := &db.MCPServer{
		ID: id, Name: name, Transport: "stdio", Command: "fixture-cmd",
		Enabled: true, Env: json.RawMessage(`null`),
	}
	if err := prepareMCPSave(pg, incoming); err != nil {
		t.Fatal(err)
	}
	if string(incoming.Args) != `["--sandbox"]` {
		t.Fatalf("args=%s", incoming.Args)
	}
}

func TestPrepareMCPSavePreservesStdioArgsWhenNullJSON(t *testing.T) {
	m := testManagerPG(t)
	pg := m.pg
	name := uniqueMCPName(t)
	id, err := pg.SaveMCP(&db.MCPServer{
		Name: name, Transport: "stdio", Command: "fixture-cmd",
		Args: json.RawMessage(`["--sandbox"]`),
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteMCP(id) })
	incoming := &db.MCPServer{
		ID: id, Name: name, Transport: "stdio", Command: "fixture-cmd",
		Args: json.RawMessage(`null`), Enabled: true,
	}
	if err := prepareMCPSave(pg, incoming); err != nil {
		t.Fatal(err)
	}
	if string(incoming.Args) != `["--sandbox"]` {
		t.Fatalf("args=%s", incoming.Args)
	}
}
