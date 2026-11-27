package db

import (
	"database/sql"
	"fmt"
)

// lockActivityAppend makes activity IDs a committed prefix within one
// exploration. Sequence allocation alone does not imply commit order: a delayed
// lower-ID insert could otherwise appear after an SSE/history cursor has passed
// it. Every live writer takes this transaction lock BEFORE its INSERT allocates
// an ID, and retains it through commit. Acquire it before locking graph rows too,
// so cancellation/follow-up writers cannot deadlock with an append's FK checks.
// Different explorations do not block one another.
func lockActivityAppend(tx *sql.Tx, explorationID int64) error {
	_, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended('artex:activity:' || $1::bigint::text, 0))`, explorationID)
	if err != nil {
		return fmt.Errorf("lock activity append: %w", err)
	}
	return nil
}
