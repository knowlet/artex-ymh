package db

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestSecurityRecordPageSizeRejectsBeforeSQL(t *testing.T) {
	var d *DB
	for _, size := range []int{201, 1_000_000, int(^uint(0) >> 1)} {
		if _, _, err := d.ListCommands(nil, "", 0, size); !errors.Is(err, ErrRecordPageSize) {
			t.Fatalf("commands size=%d: %v", size, err)
		}
		if _, _, err := d.ListLLMRecords("", "", "", 0, size); !errors.Is(err, ErrRecordPageSize) {
			t.Fatalf("LLM size=%d: %v", size, err)
		}
	}
}

func TestSecurityPGRecordPagination(t *testing.T) {
	dsn := os.Getenv("ARTEX_AUTH_TEST_DSN")
	if dsn == "" {
		t.Skip("ARTEX_AUTH_TEST_DSN unset; disposable PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	admin := stdlib.OpenDB(*cfg)
	schema := fmt.Sprintf("record_security_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema + ",public"
	d := &DB{DB: stdlib.OpenDB(*cfg)}
	t.Cleanup(func() { d.Close(); admin.Exec("DROP SCHEMA " + schema + " CASCADE"); admin.Close() })
	_, err = d.Exec(`
CREATE TABLE activity(id bigserial PRIMARY KEY, exploration_id bigint, worker text, tool text,
  detail text, is_error boolean, created_at timestamptz DEFAULT now(), kind text, tool_use_id text);
CREATE TABLE llm_records(id bigserial PRIMARY KEY, ts timestamptz DEFAULT now(), model text,
  profile_name text, session_id text, task_id text, worker text, latency_ms int, input_tokens int,
  output_tokens int, cache_read int, cache_write int, status text, error text);
INSERT INTO activity(exploration_id,kind,tool,tool_use_id) SELECT 1,'tool_use','Read',i::text FROM generate_series(1,220) i;
INSERT INTO activity(exploration_id,kind,tool_use_id,detail) SELECT 1,'tool_result',i::text,'bounded output' FROM generate_series(1,220) i;
INSERT INTO llm_records(model) SELECT 'test-model' FROM generate_series(1,220);`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ page, size, count int }{
		{0, 200, 200}, {1, 200, 20}, {2, 200, 0}, {0, 0, 50}, {-1, -1, 50}, {int(^uint(0) >> 1), 200, 0},
	} {
		commands, total, err := d.ListCommands(nil, "", tt.page, tt.size)
		if err != nil || total != 220 || len(commands) != tt.count {
			t.Fatalf("commands page=%d size=%d count=%d total=%d err=%v", tt.page, tt.size, len(commands), total, err)
		}
		if len(commands) > 0 && commands[0].Output != "bounded output" {
			t.Fatal("paired tool output was lost")
		}
		records, total, err := d.ListLLMRecords("test-model", "", "", tt.page, tt.size)
		if err != nil || total != 220 || len(records) != tt.count {
			t.Fatalf("LLM page=%d size=%d count=%d total=%d err=%v", tt.page, tt.size, len(records), total, err)
		}
	}
}
