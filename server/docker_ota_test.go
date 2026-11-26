package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Autumn-27/artex/selfupdate"
)

type otaHandlerTransport struct{ handler http.Handler }

func (t otaHandlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

func otaFixture(t *testing.T, handler http.Handler) *Server {
	t.Helper()
	stateDir := t.TempDir()
	socket := filepath.Join(t.TempDir(), "updater.sock")
	t.Setenv("ARTEX_OTA_SOCKET", socket)
	t.Setenv("ARTEX_OTA_STATE_DIR", stateDir)
	t.Setenv("ARTEX_OTA_HEALTH_SOCKET", filepath.Join(t.TempDir(), "health.sock"))
	d, err := newDockerOTA()
	if err != nil {
		t.Fatal(err)
	}
	d.client.Transport = otaHandlerTransport{handler: handler}
	m := &Manager{tasks: map[string]*Task{}}
	s := &Server{m: m, engine: NewEngine(m), dockerOTA: d, jwtKey: []byte(strings.Repeat("k", 32)), ctx: context.Background()}
	s.engine.otaGate = d.gate
	return s
}

func requireOTASocket(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if os.Getenv("ARTEX_OTA_REQUIRE_SOCKET_TESTS") != "1" && (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)) {
		t.Skipf("sandbox does not permit Unix sockets: %v", err)
	}
	t.Fatal(err)
}

func otaMark(t *testing.T, gate *dockerOTAGate) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(gate.stateDir, "maintenance.json"), []byte(`{"job_id":"fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDockerOTAGateSerializesAdmission(t *testing.T) {
	gate := &dockerOTAGate{stateDir: t.TempDir()}
	if !gate.enter() {
		t.Fatal("idle gate rejected work")
	}
	if gate.begin(nil) == nil {
		t.Fatal("update admitted while work was in flight")
	}
	gate.leave()
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if gate.begin(nil) == nil {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 1 || gate.enter() {
		t.Fatal("update barrier did not serialize admission")
	}
	gate.submissionFinished(true)
	if gate.enter() {
		t.Fatal("ambiguous submission reopened admission")
	}
	gate.reconcile(false)
	if !gate.enter() {
		t.Fatal("confirmed idle updater did not release transient barrier")
	}
	gate.leave()
}

func TestDockerOTARejectedIdleCheckDoesNotExposeBarrier(t *testing.T) {
	gate := &dockerOTAGate{stateDir: t.TempDir()}
	checking := make(chan struct{})
	finish := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- gate.begin(func() error {
			close(checking)
			<-finish
			return errors.New("running task")
		})
	}()
	<-checking
	work := make(chan bool, 1)
	go func() { work <- gate.enter() }()
	close(finish)
	if <-done == nil || !<-work {
		t.Fatal("rejected update leaked a transient barrier to a worker")
	}
	gate.leave()
}

func TestDockerOTAMarkerSurvivesRestartAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	old := &dockerOTAGate{stateDir: dir}
	otaMark(t, old)
	newProcess := &dockerOTAGate{stateDir: dir}
	if newProcess.enter() || newProcess.begin(nil) == nil {
		t.Fatal("new process ignored persistent maintenance")
	}
	newProcess.reconcile(false)
	if !newProcess.blocked() {
		t.Fatal("status response overrode updater-owned marker")
	}
	if err := os.Remove(filepath.Join(dir, "maintenance.json")); err != nil {
		t.Fatal(err)
	}
	if !newProcess.enter() {
		t.Fatal("marker removal did not restore admission")
	}
	newProcess.leave()
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if newProcess.enter() {
		t.Fatal("missing state mount failed open")
	}
}

func TestDockerOTAConfigurationRequiresAllMounts(t *testing.T) {
	for _, key := range []string{"ARTEX_OTA_SOCKET", "ARTEX_OTA_STATE_DIR", "ARTEX_OTA_HEALTH_SOCKET"} {
		t.Setenv(key, "")
	}
	if d, err := newDockerOTA(); d != nil || err != nil {
		t.Fatal("default deployment should keep OTA disabled")
	}
	t.Setenv("ARTEX_OTA_SOCKET", "/run/artex-updater/api.sock")
	if _, err := newDockerOTA(); err == nil {
		t.Fatal("partial configuration silently enabled OTA")
	}
}

func TestDockerOTARoutesRequireAdministrativeBearer(t *testing.T) {
	var called atomic.Int32
	s := otaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		writeJSON(w, 200, map[string]any{"enabled": true, "active": false, "state": "idle"})
	}))
	handler := s.Handler()
	for _, path := range []string{"status", "check", "apply", "rollback"} {
		method := http.MethodPost
		if path == "status" {
			method = http.MethodGet
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, "/api/update/docker/"+path+"?ticket=not-an-admin-token", strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s returned %d", path, w.Code)
		}
	}
	if called.Load() != 0 {
		t.Fatal("unauthenticated request reached the updater")
	}
	token, err := signJWT(s.jwtKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/update/docker/status", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || called.Load() != 1 {
		t.Fatalf("authenticated status failed: %d %s", w.Code, w.Body.String())
	}
	if selfupdate.InstallEnabled {
		t.Fatal("Docker integration enabled the binary self-update policy")
	}
}

func TestDockerOTARequestRejectsArbitraryImagesAndChannels(t *testing.T) {
	var called atomic.Int32
	s := otaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		writeJSON(w, 200, map[string]any{})
	}))
	for _, test := range []struct {
		handler http.HandlerFunc
		body    string
	}{
		{s.dockerOTACheck, `{"channel":"https://other.invalid/image"}`},
		{s.dockerOTACheck, `{"channel":"main","image":"evil"}`},
		{s.dockerOTACheck, `{"channel":"main"} {}`},
		{s.dockerOTAApply, `{"plan_id":"../../somewhere"}`},
		{s.dockerOTAApply, `{"plan_id":"0123456789abcdef","image":"evil"}`},
		{s.dockerOTARollback, `{"image":"evil"}`},
	} {
		w := httptest.NewRecorder()
		test.handler(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("unsafe request returned %d: %s", w.Code, test.body)
		}
	}
	if called.Load() != 0 {
		t.Fatal("unsafe input reached updater")
	}
}

func TestDockerOTAApplyRejectsRunningWorkBeforeSubmission(t *testing.T) {
	var called atomic.Int32
	s := otaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Add(1) }))
	s.m.tasks["1"] = &Task{ID: "1", Status: "running"}
	w := httptest.NewRecorder()
	s.dockerOTAApply(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"plan_id":"0123456789abcdef"}`)))
	if w.Code != http.StatusConflict || called.Load() != 0 || s.otaGate().blocked() {
		t.Fatal("running task was submitted or left a stale barrier")
	}
	if !s.engine.beginTaskOperation("1") {
		t.Fatal("rejected update stopped the existing task")
	}
	s.engine.decInflight("1")
}

func TestDockerOTAApplyHandsOffToPersistentMarker(t *testing.T) {
	var s *Server
	s = otaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apply" || r.Method != http.MethodPost {
			t.Errorf("unexpected updater request: %s %s", r.Method, r.URL.Path)
		}
		otaMark(t, s.otaGate())
		writeJSON(w, http.StatusAccepted, map[string]any{"enabled": true, "active": true, "state": "queued", "job_id": "fixture"})
	}))
	w := httptest.NewRecorder()
	s.dockerOTAApply(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"plan_id":"0123456789abcdef"}`)))
	if w.Code != http.StatusAccepted || !s.otaGate().blocked() || s.engine.beginTaskOperation("1") {
		t.Fatalf("marker handoff failed: %d %s", w.Code, w.Body.String())
	}
}

func TestDockerOTAMissingMarkerDoesNotReopenAdmission(t *testing.T) {
	s := otaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 202, map[string]any{"active": true, "state": "queued"})
	}))
	w := httptest.NewRecorder()
	s.dockerOTAApply(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"plan_id":"0123456789abcdef"}`)))
	if w.Code != http.StatusBadGateway || !s.otaGate().blocked() {
		t.Fatal("accepted job without a durable marker failed open")
	}
}

func TestDockerOTAMaintenanceBlocksMutationAndBackgroundAdmission(t *testing.T) {
	s := otaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	otaMark(t, s.otaGate())
	called := false
	handler := s.dockerOTAMutations(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/tasks", nil))
	if w.Code != http.StatusServiceUnavailable || called {
		t.Fatal("API mutation crossed maintenance barrier")
	}
	if _, err := s.admitTask(&Task{ID: "1"}, "resume"); !errors.Is(err, errDockerOTAMaintenance) {
		t.Fatal("task admission crossed maintenance barrier")
	}
	// These must return before dereferencing unconfigured backing stores.
	s.reconcileConcurrency()
	(&Scheduler{s: s}).step()
	s.StartTriggeredRun("agent", "title", "message", 0, false, "", "")
	if err := s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}
}

func TestDockerOTADeadlineWaitsBeforeMarkingSettling(t *testing.T) {
	gate := &dockerOTAGate{stateDir: t.TempDir()}
	otaMark(t, gate)
	e := NewEngine(nil)
	e.otaGate = gate
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.settleTask(ctx, &Task{ID: "1"})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("maintenance wait ignored cancellation")
	}
	if e.isSettling("1") {
		t.Fatal("maintenance stranded a paused task in settling")
	}
}

func TestDockerOTAReadinessUsesPrivateSocketAndDatabase(t *testing.T) {
	s := otaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	defer cancel()
	otaMark(t, s.otaGate())
	if err := s.StartDockerOTAReadiness(); err != nil {
		requireOTASocket(t, err)
	}
	info, err := os.Stat(s.dockerOTA.healthSocket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("readiness socket permissions are not private")
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", s.dockerOTA.healthSocket)
	}}, Timeout: time.Second}
	resp, err := client.Get("http://localhost/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var result struct {
		Ready       bool `json:"ready"`
		Maintenance bool `json:"maintenance"`
		Idle        bool `json:"idle"`
		Protocol    int  `json:"ota_protocol"`
	}
	if json.Unmarshal(data, &result) != nil || result.Ready || !result.Maintenance || !result.Idle || result.Protocol != 1 || resp.StatusCode != 503 {
		t.Fatalf("unavailable DB was reported ready: %d %s", resp.StatusCode, data)
	}
}

func TestDockerOTAReadinessRechecksIdleIndependentlyOfUICaller(t *testing.T) {
	s := otaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	readIdle := func() bool {
		w := httptest.NewRecorder()
		s.dockerOTAReadiness(w, httptest.NewRequest(http.MethodGet, "/health", nil))
		var result struct {
			Idle bool `json:"idle"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Idle
	}
	s.m.tasks["1"] = &Task{ID: "1", Status: "running"}
	otaMark(t, s.otaGate()) // simulate direct updater UDS caller, bypassing UI
	if readIdle() {
		t.Fatal("running work accepted because marker existed")
	}
	s.m.tasks["1"] = &Task{ID: "1", Status: "paused", Paused: true}
	if !readIdle() {
		t.Fatal("paused, drained task was not idle")
	}
	s.chatBusy = map[string]bool{"conv-1": true}
	if readIdle() {
		t.Fatal("running conversation ignored by readiness")
	}
	delete(s.chatBusy, "conv-1")
	s.otaGate().mu.Lock()
	s.otaGate().inflight++
	s.otaGate().mu.Unlock()
	if readIdle() {
		t.Fatal("in-flight operation ignored by readiness")
	}
	s.otaGate().leave()
}

func TestDockerOTAUnixClientConnectsOnlyToConfiguredSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	requireOTASocket(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "artex-updater" || r.URL.Path != "/v1/status" {
			t.Errorf("unexpected local request: %s %s", r.Host, r.URL.Path)
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": false, "state": "idle"})
	})}
	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })
	t.Setenv("ARTEX_OTA_SOCKET", socket)
	t.Setenv("ARTEX_OTA_STATE_DIR", t.TempDir())
	t.Setenv("ARTEX_OTA_HEALTH_SOCKET", filepath.Join(t.TempDir(), "health.sock"))
	d, err := newDockerOTA()
	if err != nil {
		t.Fatal(err)
	}
	data, status, err := d.call(context.Background(), http.MethodGet, "/v1/status", nil)
	if err != nil || status != http.StatusOK || !strings.Contains(string(data), `"idle"`) {
		t.Fatalf("Unix client failed: %d %s %v", status, data, err)
	}
}
