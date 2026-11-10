package db

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestSecurityPGDSLRestrictions(t *testing.T) {
	// Use only the explicit disposable-test DSN. A separate schema and the
	// actual application schema exercise all three store consumers safely.
	dsn := os.Getenv("ARTEX_AUTH_TEST_DSN")
	if dsn == "" {
		t.Skip("ARTEX_AUTH_TEST_DSN unset; isolated PostgreSQL test not run")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid isolated PostgreSQL configuration")
	}
	admin := stdlib.OpenDB(*cfg)
	schema := fmt.Sprintf("asset_dsl_security_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	d := &DB{DB: stdlib.OpenDB(*cfg)}
	t.Cleanup(func() {
		d.Close()
		admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		admin.Close()
	})
	if _, err := d.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("DSL security fixture", "read local fixture rows", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := d.CreateTask("foreign DSL fixture", "unrelated scope", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO task_scope(task_id,kind,domain) VALUES($1,'root_domain','in.example')", task.ID); err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		id        int64
		typ, root string
		port      int
		taskID    int64
	}{
		{1, "service", "in.example", 80, foreign.ID},
		{2, "service", "out.example", 80, foreign.ID},
		{3, "endpoint", "in.example", 80, task.ID},
		{4, "service", "in.example", 443, task.ID},
		{5, "service", "out.example", 443, foreign.ID},
		{6, "service", "in.example", 22, task.ID},
	}
	for _, row := range fixtures {
		domain := fmt.Sprintf("fixture%d.%s", row.id, row.root)
		_, err := d.Exec("INSERT INTO assets(id,type,domain,root_domain,port,task_ids) VALUES($1,$2,$3,$4,$5,$6::bigint[])",
			row.id, row.typ, domain, row.root, row.port, []int64{row.taskID})
		if err != nil {
			t.Fatal(err)
		}
	}
	store := d.Assets()
	for _, tc := range []struct {
		name, dsl, typ string
		taskID         int64
		scope          bool
		want           []int64
	}{
		{"task and type", "port=80 OR port=443", "service", task.ID, false, []int64{4}},
		{"task only", "port=80 OR port=443", "", task.ID, false, []int64{3, 4}},
		{"type only", "port=80 OR port=443", "service", 0, false, []int64{1, 2, 4, 5}},
		{"declared scope and type", "port=80 OR port=443", "service", task.ID, true, []int64{1, 4}},
		{"declared scope only", "port=80 OR port=443", "", task.ID, true, []int64{1, 3, 4}},
		{"nested expression", "port=80 OR (port=443 AND port>100)", "service", task.ID, true, []int64{1, 4}},
		{"ordinary leaf", "port=443", "service", task.ID, true, []int64{4}},
		{"non-task global", "port=80 OR port=443", "", 0, true, []int64{1, 2, 3, 4, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rows []*Asset
			var err error
			if tc.scope {
				rows, err = store.QueryDSLInScope(tc.dsl, tc.typ, tc.taskID, 100, 0)
			} else {
				count, countErr := store.CountDSL(tc.dsl, tc.typ, tc.taskID)
				if countErr != nil || count != len(tc.want) {
					t.Fatalf("CountDSL=%d want=%d err=%v", count, len(tc.want), countErr)
				}
				rows, err = store.QueryDSL(tc.dsl, tc.typ, tc.taskID, 100, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			got := make([]int64, 0, len(rows))
			for _, row := range rows {
				got = append(got, row.ID)
			}
			slices.Sort(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("query returned ids=%v want=%v", got, tc.want)
			}
		})
	}
}
