package server

import (
	"time"

	"github.com/Autumn-27/artex/agent"
)

// A transient model outage gets its own cooldown instead of the normal ten
// minute planner heartbeat. Edge notifications cannot bypass the cooldown, so
// many workers finishing during an outage cannot create a retry storm.
type plannerRetrySchedule struct {
	failures int
	readyAt  time.Time
}

func (s *plannerRetrySchedule) record(now time.Time, err error) time.Duration {
	if !agent.IsTransientModelError(err) {
		*s = plannerRetrySchedule{}
		return 0
	}
	s.failures++
	delay := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}[min(s.failures, 4)-1]
	s.readyAt = now.Add(delay)
	return delay
}

func (s *plannerRetrySchedule) remaining(now time.Time) time.Duration {
	return max(s.readyAt.Sub(now), 0)
}

func (s *plannerRetrySchedule) nextDelay(now time.Time, heartbeat time.Duration) time.Duration {
	if s.failures == 0 {
		return heartbeat
	}
	// The timer may become due between a skipped edge notification and rearming.
	// A short positive delay avoids a hot loop without renewing the cooldown.
	return min(max(s.remaining(now), time.Second), heartbeat)
}
