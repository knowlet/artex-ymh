package db

import (
	"database/sql"
	"reflect"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSecurityDSLRestrictionsApplyToWholeExpression(t *testing.T) {
	// The numeric DSL is portable SQL. Execute it against an in-memory engine
	// to verify precedence even when PostgreSQL is not configured locally.
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec("CREATE TABLE assets(id INTEGER, port INTEGER, type TEXT, task_id INTEGER);" +
		"INSERT INTO assets VALUES(1,80,'service',1),(2,80,'endpoint',2)," +
		"(3,443,'service',2),(4,443,'service',1),(5,22,'service',1),(6,80,'service',2)"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, dsl, suffix string
		extra             []any
		want              []int
	}{
		{"task", "port=80 OR port=443", " AND task_id=$3", []any{1}, []int{1, 4}},
		{"type", "port=80 OR port=443", " AND type=$3", []any{"service"}, []int{1, 3, 4, 6}},
		{"task and type", "port=80 OR port=443", " AND type=$3 AND task_id=$4", []any{"service", 1}, []int{1, 4}},
		{"nested", "port=80 OR (port=443 AND port>100)", " AND task_id=$4", []any{1}, []int{1, 4}},
		{"ordinary leaf", "port=80", " AND task_id=$2", []any{1}, []int{1}},
		{"global remains global", "port=80 OR port=443", "", nil, []int{1, 2, 3, 4, 6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node, err := ParseDSL(tc.dsl)
			if err != nil {
				t.Fatal(err)
			}
			where, args, err := buildDSLWhere(node)
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, tc.extra...)
			rows, err := conn.Query("SELECT id FROM assets WHERE "+where+tc.suffix+" ORDER BY id", args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var got []int
			for rows.Next() {
				var id int
				if err := rows.Scan(&id); err != nil {
					t.Fatal(err)
				}
				got = append(got, id)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("restriction escaped: ids=%v want=%v SQL=%s%s", got, tc.want, where, tc.suffix)
			}
		})
	}
}
