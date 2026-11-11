package server

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestMCPStdioScrubsInheritedSecretValues(t *testing.T) {
	t.Setenv("ARTEX_PG_DSN", "synthetic-parent-secret")
	t.Setenv("UNRELATED_SECRET", "synthetic-parent-secret")
	t.Setenv("OPENAI_API_KEY", "synthetic-parent-secret")
	t.Setenv("MCP_CONFIGURED_KEY", "synthetic-parent-secret")
	args, _ := json.Marshal([]string{"-test.run=^TestMCPEnvironmentChild$"})
	env, _ := json.Marshal(map[string]string{"ARTEX_MCP_ENV_TEST": "1", "MCP_CONFIGURED_KEY": "synthetic-explicit-key"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl, err := connectMCP(ctx, &db.MCPServer{Name: "fixture", Transport: "stdio", Command: os.Args[0], Args: args, Env: env})
	if err != nil {
		t.Fatalf("sanitized child handshake failed: %v", err)
	}
	defer cl.Close()
	if os.Getenv("UNRELATED_SECRET") != "synthetic-parent-secret" {
		t.Fatal("child sanitization modified the parent process environment")
	}
}

func TestMCPEnvironmentChild(t *testing.T) {
	if os.Getenv("ARTEX_MCP_ENV_TEST") != "1" {
		return
	}
	if os.Getenv("ARTEX_PG_DSN") != "" || os.Getenv("UNRELATED_SECRET") != "" || os.Getenv("OPENAI_API_KEY") != "" ||
		os.Getenv("MCP_CONFIGURED_KEY") != "synthetic-explicit-key" || os.Getenv("PATH") == "" {
		os.Exit(42)
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			os.Exit(43)
		}
		if req.Method == "initialize" {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}}})
		}
	}
	os.Exit(0)
}
