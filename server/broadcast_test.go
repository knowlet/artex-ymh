package server

import (
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Once a subscriber misses a durable activity, it must reconnect before seeing
// any later ID. Otherwise streamActivity advances Last-Event-ID past the gap and
// its database replay can never recover the missing row.
func TestBroadcasterOverflowDisconnectsBeforeCursorCanSkip(t *testing.T) {
	b := NewBroadcaster()
	slow, unsubscribeSlow := b.Subscribe("task")
	defer unsubscribeSlow()
	fast, unsubscribeFast := b.Subscribe("task")
	defer unsubscribeFast()
	other, unsubscribeOther := b.Subscribe("other-task")
	defer unsubscribeOther()

	for id := int64(1); id <= 257; id++ {
		b.Publish("task", db.Activity{ID: id})
		if got := <-fast; got.ID != id {
			t.Fatalf("healthy subscriber received ID %d, want %d", got.ID, id)
		}
	}
	for id := int64(1); id <= 256; id++ {
		if got, ok := <-slow; !ok || got.ID != id {
			t.Fatalf("buffered prefix = %d (open=%v), want %d", got.ID, ok, id)
		}
	}
	select {
	case a, ok := <-slow:
		if ok {
			t.Fatalf("overflowed stream stayed open with ID %d", a.ID)
		}
	default:
		t.Fatal("overflowed stream stayed open instead of reconnecting for database replay")
	}

	// Both handler cleanup and later publishes remain safe after eviction. A
	// healthy subscriber and an unrelated task are unaffected by the slow peer.
	unsubscribeSlow()
	unsubscribeSlow()
	b.Publish("task", db.Activity{ID: 258})
	if got := <-fast; got.ID != 258 {
		t.Fatalf("healthy subscriber after overflow = %d, want 258", got.ID)
	}
	select {
	case a := <-other:
		t.Fatalf("another task received activity %d", a.ID)
	default:
	}

	reconnected, unsubscribeReconnected := b.Subscribe("task")
	defer unsubscribeReconnected()
	b.Publish("task", db.Activity{ID: 259})
	if got := <-reconnected; got.ID != 259 {
		t.Fatalf("reconnected subscriber = %d, want 259", got.ID)
	}
}

func TestBroadcasterConcurrentOverflowAndUnsubscribe(t *testing.T) {
	b := NewBroadcaster()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				ch, unsubscribe := b.Subscribe("task")
				var cleanup sync.WaitGroup
				cleanup.Go(unsubscribe)
				cleanup.Go(unsubscribe)
				cleanup.Wait()
				for range ch {
				}
			}
		})
		wg.Go(func() {
			for id := int64(1); id <= 1000; id++ {
				b.Publish("task", db.Activity{ID: id})
			}
		})
	}
	wg.Wait()
	if len(b.subs) != 0 {
		t.Fatalf("subscriptions leaked after cleanup: %d tasks", len(b.subs))
	}
}
