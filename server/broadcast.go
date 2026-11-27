package server

import (
	"sync"

	"github.com/Autumn-27/artex/db"
)

// Broadcaster is a per-task in-process pub/sub for live activity events. The
// engine publishes each appended activity at its single emit point; SSE handlers
// subscribe per task. Storage (activity table) and the live stream come from the
// same emit path. The database remains the replay source of truth; notifications
// can arrive out of order when concurrent writers finish publishing.
type Broadcaster struct {
	mu   sync.Mutex
	subs map[string]map[chan db.Activity]struct{} // task id -> set of subscriber channels
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subs: map[string]map[chan db.Activity]struct{}{}}
}

// Subscribe returns a buffered channel of activities for a task plus an
// unsubscribe func the caller must invoke (defer) to release it.
func (b *Broadcaster) Subscribe(task string) (<-chan db.Activity, func()) {
	ch := make(chan db.Activity, 256)
	b.mu.Lock()
	if b.subs[task] == nil {
		b.subs[task] = map[chan db.Activity]struct{}{}
	}
	b.subs[task][ch] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			if m := b.subs[task]; m != nil {
				if _, subscribed := m[ch]; subscribed {
					delete(m, ch)
					close(ch)
				}
				if len(m) == 0 {
					delete(b.subs, task)
				}
			}
			b.mu.Unlock()
		})
	}
}

// Publish fans an activity out to all subscribers of a task. Non-blocking: if a
// subscriber's buffer is full, disconnect it before any later event can advance
// its cursor past the missing row. The buffered prefix is still readable; after
// draining it the SSE handler closes and the client replays from the DB. Closing
// and removing the channel under the same lock as unsubscribe makes eviction and
// handler cleanup safe to race, without letting slow clients stall the engine.
func (b *Broadcaster) Publish(task string, a db.Activity) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subs[task]
	for ch := range subs {
		select {
		case ch <- a:
		default:
			delete(subs, ch)
			close(ch)
		}
	}
	if len(subs) == 0 {
		delete(b.subs, task)
	}
}
