package server

import (
	"context"
	"testing"
)

// API fixtures run the real server during the test and join its background
// writers before testing removes their temporary directories. A Background
// context leaked restored task engines into later tests and raced RemoveAll.
func newLifecycleTestServer(t *testing.T, m *Manager, skillDir, dataDir, keyDir string) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	s := New(ctx, m, skillDir, dataDir, keyDir)
	t.Cleanup(func() {
		cancel()
		for _, task := range m.List() {
			s.engine.StopTask(task.ID)
		}
		s.archiveWG.Wait()
		if s.side != nil {
			<-s.side.done
		}
	})
	return s
}
