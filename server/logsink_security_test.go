package server

import (
	"io"
	"sync"
	"testing"
	"time"
)

func TestLogSinkConcurrentUnsubscribeAndFanout(t *testing.T) {
	sink := &logSinkT{cap: 64, subs: map[chan LogLine]struct{}{}, out: io.Discard}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			for range 1000 {
				sink.add(LogLine{Text: "concurrent log"})
			}
		})
		wg.Go(func() {
			<-start
			for range 250 {
				ch, unsubscribe := sink.subscribe()
				unsubscribe()
				unsubscribe()
				for range ch {
				}
			}
		})
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("log fanout or unsubscribe blocked")
	}
	lines, seq := sink.recent(0, 64)
	if seq != 8000 || len(lines) != 64 || len(sink.subs) != 0 {
		t.Fatalf("lost logs/subscriptions: seq=%d lines=%d subs=%d", seq, len(lines), len(sink.subs))
	}
}

func TestLogSinkSlowSubscriberAndIdempotentClose(t *testing.T) {
	sink := &logSinkT{cap: 32, subs: map[chan LogLine]struct{}{}, out: io.Discard}
	ch, unsubscribe := sink.subscribe()
	done := make(chan struct{})
	go func() {
		for range 1000 {
			sink.add(LogLine{Text: "full subscriber"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slow subscriber blocked logging")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(unsubscribe)
	}
	wg.Wait()
	for range ch {
	}
	sink.add(LogLine{Text: "after close"})
}
