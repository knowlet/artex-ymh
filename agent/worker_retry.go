package agent

import (
	"fmt"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type WorkerRetryCheckpoint struct {
	Records  int
	LastUUID string
}

// ModelRetryCheckpoint marks the durable history before an attempt. Providers
// may reuse tool IDs each turn, so an older result with the same ID cannot prove
// that a tool executed by this attempt was committed.
func (w *Worker) ModelRetryCheckpoint(explorationID, intentID int64) (WorkerRetryCheckpoint, error) {
	if w.tx == nil {
		return WorkerRetryCheckpoint{}, fmt.Errorf("worker model recovery requires transcript persistence")
	}
	records, err := w.tx.Load(w.tx.MainPath(WorkerSessionID(explorationID, intentID)))
	if err != nil {
		return WorkerRetryCheckpoint{}, err
	}
	return WorkerRetryCheckpoint{Records: len(records), LastUUID: transcript.LastUUID(records)}, nil
}

// CheckModelRetryTranscript verifies that a later run can continue the exact
// intent, including every tool result observed by the engine. A failed/missing
// transcript must never silently turn recovery into a fresh execution.
func (w *Worker) CheckModelRetryTranscript(explorationID, intentID int64, completedToolIDs []string) error {
	return w.CheckModelRetryTranscriptSince(explorationID, intentID, WorkerRetryCheckpoint{}, completedToolIDs)
}

func (w *Worker) CheckModelRetryTranscriptSince(explorationID, intentID int64, checkpoint WorkerRetryCheckpoint, completedToolIDs []string) error {
	if w.tx == nil {
		return fmt.Errorf("worker model recovery requires transcript persistence")
	}
	records, err := w.tx.Load(w.tx.MainPath(WorkerSessionID(explorationID, intentID)))
	if err != nil {
		return fmt.Errorf("worker model recovery cannot load transcript: %w", err)
	}
	messages, _ := transcript.Messages(records)
	if err := validateWorkerRetryTranscript(messages, nil); err != nil {
		return err
	}
	if checkpoint.Records < 0 || checkpoint.Records > len(records) ||
		checkpoint.Records > 0 && records[checkpoint.Records-1].UUID != checkpoint.LastUUID {
		return fmt.Errorf("worker model recovery transcript checkpoint changed")
	}
	// Norma re-records the kept tail after compaction. Without execution UUIDs,
	// those copied results cannot establish that a later repeated tool ID was
	// committed. Preserve the transcript for manual inspection instead of replay.
	if len(completedToolIDs) > 0 {
		for _, record := range records[checkpoint.Records:] {
			if record.Type == "boundary" {
				return fmt.Errorf("worker model recovery cannot verify tool executions across a compaction boundary")
			}
		}
	}
	current, _ := transcript.Messages(records[checkpoint.Records:])
	return validateWorkerRetryTranscript(current, completedToolIDs)
}

func validateWorkerRetryTranscript(messages []llm.Message, completedToolIDs []string) error {
	if len(messages) == 0 {
		return fmt.Errorf("worker model recovery transcript is empty")
	}
	pending := map[string]int{}
	results := map[string]int{}
	for _, message := range messages {
		for _, block := range message.Content {
			switch block.Type {
			case llm.BlockToolUse:
				pending[block.ID]++
			case llm.BlockToolResult:
				if pending[block.ToolUseID] > 1 {
					pending[block.ToolUseID]--
				} else {
					delete(pending, block.ToolUseID)
				}
				results[block.ToolUseID]++
			}
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("worker model recovery transcript contains unfinished tool calls")
	}
	for _, id := range completedToolIDs {
		if id == "" || results[id] == 0 {
			return fmt.Errorf("worker model recovery transcript is missing an observed tool result")
		}
		results[id]--
	}
	return nil
}
