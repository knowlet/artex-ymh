package server

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/context1337"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const context1337TaskBudget = 16

// Operator configuration is captured once at wiring/startup. It never comes
// from task prose, LLM input, editable tool defaults or remote provider content.
type context1337Exercises struct {
	client *context1337.Client
	tasks  map[int64]int
	mu     sync.Mutex
}

func loadContext1337Exercises(getenv func(string) string) (*context1337Exercises, error) {
	if getenv("ARTEX_CONTEXT1337_EXERCISES") == "" || getenv("ARTEX_CONTEXT1337_EXERCISES") == "false" {
		return nil, nil
	}
	if getenv("ARTEX_CONTEXT1337_EXERCISES") != "true" {
		return nil, errors.New("Context1337 exercises disabled: enable flag must be true or false")
	}
	// Legacy CLI credentials must not be inherited by agent subprocesses.
	if getenv("ARTEX_CONTEXT1337_API_KEY") != "" {
		return nil, errors.New("Context1337 exercises disabled: remove the CLI API_KEY environment value and use API_KEY_FILE")
	}
	parts := strings.Split(getenv("ARTEX_CONTEXT1337_TASK_IDS"), ",")
	if len(parts) > 32 {
		return nil, errors.New("Context1337 exercises disabled: at most 32 exact task IDs are permitted")
	}
	tasks := make(map[int64]int, len(parts))
	for _, part := range parts {
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != part {
			return nil, errors.New("Context1337 exercises disabled: provide comma-separated positive canonical task IDs")
		}
		if _, duplicate := tasks[id]; duplicate {
			return nil, errors.New("Context1337 exercises disabled: duplicate task ID")
		}
		tasks[id] = 0
	}
	key, err := readContext1337Secret(getenv("ARTEX_CONTEXT1337_API_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	client, err := context1337.NewClient(getenv("ARTEX_CONTEXT1337_URL"), key)
	if err != nil {
		return nil, errors.New("Context1337 exercises disabled: invalid fixed origin or credential")
	}
	return &context1337Exercises{client: client, tasks: tasks}, nil
}

func readContext1337Secret(path string) (string, error) {
	invalid := errors.New("Context1337 exercises disabled: API_KEY_FILE must be a private regular file containing one bounded key")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		return "", invalid
	}
	f, err := os.Open(path)
	if err != nil {
		return "", invalid
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", invalid
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) < 1 || len(b) > 4096 {
		return "", invalid
	}
	// Permit a single conventional trailing newline; all other whitespace is
	// rejected by NewClient. Never return a path or file contents in errors.
	return strings.TrimSuffix(string(b), "\n"), nil
}

func (p *context1337Exercises) approved(taskID int64) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.tasks[taskID]
	return ok
}

func (p *context1337Exercises) reserve(taskID int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, ok := p.tasks[taskID]
	if !ok || n >= context1337TaskBudget {
		return false
	}
	p.tasks[taskID] = n + 1
	return true
}

// Each check is live and fails closed. In particular, ToolResolve's general
// DB-error fallback cannot grant this optional external-network capability.
func context1337RunAllowed(ctx context.Context, pg *db.DB, role string, ri agent.RunInfo) bool {
	if ctx.Err() != nil || pg == nil || (role != "planner" && role != "worker") || ri.TaskID <= 0 || ri.ExplorationID <= 0 || ri.SessionID != "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var allowed bool
	err := pg.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM tasks t, tools k
		WHERE t.id=$1 AND t.exploration_id=$2 AND t.deleted_at IS NULL
		AND t.status='running' AND NOT t.paused AND NOT t.queued
		AND (t.deadline_at IS NULL OR t.deadline_at > now())
		AND k.key=$3 AND k.system AND k.kind='builtin' AND k.enabled
		AND k.agents ? $4
	)`, ri.TaskID, ri.ExplorationID, context1337.ToolName, role).Scan(&allowed)
	return err == nil && allowed
}

func (p *context1337Exercises) tool(ctx context.Context, pg *db.DB, role string) actool.CoreTool {
	ri := agent.RunInfoFrom(ctx)
	if !p.approved(ri.TaskID) || !context1337RunAllowed(ctx, pg, role, ri) {
		return nil
	}
	return context1337.Tool(p.client, func(callCtx context.Context) bool {
		return agent.RunInfoFrom(callCtx) == ri && p.approved(ri.TaskID) &&
			context1337RunAllowed(callCtx, pg, role, ri) && p.reserve(ri.TaskID)
	})
}

func configuredContext1337Exercises() *context1337Exercises {
	p, err := loadContext1337Exercises(os.Getenv)
	if err != nil {
		// Optional provider failure must never stop service initialization.
		log.Print(err)
	}
	return p
}
