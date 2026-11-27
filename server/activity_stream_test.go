package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func newActivityStreamFixture(t *testing.T) (*Server, *Task) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("ARTEX_PG_DSN required for activity stream regression")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	taskRow, err := pg.CreateTask("activity stream fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(taskRow.ID) })
	task := &Task{ID: strconv.FormatInt(taskRow.ID, 10), ExpID: taskRow.ExplorationID, Store: pg.Exploration(taskRow.ExplorationID)}
	s := &Server{m: &Manager{pg: pg, tasks: map[string]*Task{task.ID: task}}, engine: &Engine{bc: NewBroadcaster()}}
	return s, task
}

func readActivityStreamIDs(t *testing.T, body io.Reader, want []int64) {
	t.Helper()
	scanner := bufio.NewScanner(body)
	for _, id := range want {
		found := false
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "id: ") {
				if line != fmt.Sprintf("id: %d", id) {
					t.Fatalf("stream advanced past an undelivered activity: got %q, want id: %d", line, id)
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("activity %d was not delivered: %v", id, scanner.Err())
		}
	}
}

func TestActivityStreamReplaysReorderedNotifications(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		t.Run(fmt.Sprintf("intent_scoped=%v", scoped), func(t *testing.T) {
			s, task := newActivityStreamFixture(t)
			intentID, err := task.Store.AddIntent(map[string]any{"summary": "stream fixture"}, 1, nil, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			query := "?task=" + task.ID
			if scoped {
				query += "&intent=" + strconv.FormatInt(intentID, 10)
			}
			httpServer := httptest.NewServer(http.HandlerFunc(s.streamActivity))
			defer httpServer.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+query, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := httpServer.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("stream status = %d", res.StatusCode)
			}
			// Response headers are flushed after subscription and initial replay,
			// so these rows are guaranteed to exercise the live path.
			first := db.Activity{NodeID: &intentID, Worker: "worker", Kind: "text", Summary: "first"}
			first.ID, err = task.Store.AppendActivity(first)
			if err != nil {
				t.Fatal(err)
			}
			ignored := db.Activity{Worker: "planner", Kind: "text", Summary: "other session"}
			ignored.ID, err = task.Store.AppendActivity(ignored)
			if err != nil {
				t.Fatal(err)
			}
			last := db.Activity{NodeID: &intentID, Worker: "worker", Kind: "text", Summary: "last"}
			last.ID, err = task.Store.AppendActivity(last)
			if err != nil {
				t.Fatal(err)
			}
			// A concurrent publisher can be delayed after its INSERT commits.
			// The later publication must wake an ordered DB replay, not become
			// the cursor itself and suppress the first row forever.
			s.engine.bc.Publish(task.ID, last)
			s.engine.bc.Publish(task.ID, first)
			s.engine.bc.Publish(task.ID, ignored)
			want := []int64{first.ID, ignored.ID, last.ID}
			if scoped {
				want = []int64{first.ID, last.ID}
			}
			readActivityStreamIDs(t, res.Body, want)
		})
	}
}

func TestActivityStreamReconnectReplaysEveryBatch(t *testing.T) {
	s, task := newActivityStreamFixture(t)
	ids := make([]int64, 505)
	for i := range ids {
		var err error
		ids[i], err = task.Store.AppendActivity(db.Activity{Worker: "worker", Kind: "text", Summary: fmt.Sprint(i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	httpServer := httptest.NewServer(http.HandlerFunc(s.streamActivity))
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// A reconnect's Last-Event-ID takes precedence over the original URL cursor.
	// The remaining 503 events require two database replay batches.
	url := fmt.Sprintf("%s?task=%s&since=%d", httpServer.URL, task.ID, ids[len(ids)-1])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Last-Event-ID", strconv.FormatInt(ids[1], 10))
	res, err := httpServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d", res.StatusCode)
	}
	readActivityStreamIDs(t, res.Body, ids[2:])
}
