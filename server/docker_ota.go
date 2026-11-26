package server

// Docker OTA is deliberately separate from the binary self-update policy. The
// application can ask a locally provisioned updater to install a checked plan;
// it never receives Docker credentials, a Docker socket, or arbitrary commands.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/selfupdate"
)

const dockerOTAMaintenanceMessage = "Docker 更新維護中，暫停接受新的操作；請在系統設定查看更新狀態"

var errDockerOTAMaintenance = errors.New(dockerOTAMaintenanceMessage)
var dockerOTAPlanID = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,128}$`)

// A successful submission is protected first by pending and then by the
// updater-owned marker. enter/begin serialize that handoff with new work.
// The marker directory is mounted read-only into ARTEX, outside its workspace.
type dockerOTAGate struct {
	mu         sync.Mutex
	stateDir   string
	pending    bool
	submitting bool
	inflight   int
}

func (g *dockerOTAGate) marker() (bool, error) {
	dir, err := os.Lstat(g.stateDir)
	if err != nil || !dir.IsDir() {
		return true, errors.New("Docker OTA 狀態目錄無法讀取")
	}
	_, err = os.Lstat(filepath.Join(g.stateDir, "maintenance.json"))
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func (g *dockerOTAGate) enter() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	marked, err := g.marker()
	if g.pending || marked || err != nil {
		return false
	}
	g.inflight++
	return true
}

func (g *dockerOTAGate) leave() {
	if g != nil {
		g.mu.Lock()
		g.inflight--
		g.mu.Unlock()
	}
}

func (g *dockerOTAGate) blocked() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	marked, err := g.marker()
	return g.pending || marked || err != nil
}

func (g *dockerOTAGate) begin(idle func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	marked, err := g.marker()
	if err != nil {
		return err
	}
	if g.pending || marked {
		return errDockerOTAMaintenance
	}
	if g.inflight != 0 {
		return errors.New("仍有操作執行中，請等候完成後再更新")
	}
	// Check before publishing pending. A rejected update must never make an
	// existing worker observe a transient maintenance barrier and exit its loop.
	if idle != nil {
		if err := idle(); err != nil {
			return err
		}
	}
	g.pending, g.submitting = true, true
	return nil
}

func (g *dockerOTAGate) submissionFinished(uncertain bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.submitting = false
	// An ambiguous network failure must not reopen task admission. A later
	// status response can release this transient barrier after reconciliation.
	if !uncertain {
		g.pending = false
	}
}

func (g *dockerOTAGate) reconcile(active bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	marked, err := g.marker()
	if !active && !marked && err == nil && !g.submitting {
		g.pending = false
	}
}

type dockerOTA struct {
	gate         *dockerOTAGate
	client       *http.Client
	healthSocket string
}

func newDockerOTA() (*dockerOTA, error) {
	socket := strings.TrimSpace(os.Getenv("ARTEX_OTA_SOCKET"))
	stateDir := strings.TrimSpace(os.Getenv("ARTEX_OTA_STATE_DIR"))
	healthSocket := strings.TrimSpace(os.Getenv("ARTEX_OTA_HEALTH_SOCKET"))
	if socket == "" && stateDir == "" && healthSocket == "" {
		return nil, nil
	}
	for _, path := range []string{socket, stateDir, healthSocket} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("ARTEX_OTA_SOCKET、ARTEX_OTA_STATE_DIR 與 ARTEX_OTA_HEALTH_SOCKET 必須是絕對路徑")
		}
	}
	gate := &dockerOTAGate{stateDir: stateDir}
	if _, err := gate.marker(); err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
		},
		MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second,
	}
	return &dockerOTA{gate: gate, healthSocket: healthSocket, client: &http.Client{
		Transport: transport, Timeout: 6 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (s *Server) otaGate() *dockerOTAGate {
	if s == nil || s.dockerOTA == nil {
		return nil
	}
	return s.dockerOTA.gate
}

func (s *Server) dockerOTAMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions ||
			strings.HasPrefix(r.URL.Path, "/api/update/docker/") || r.URL.Path == "/api/auth/login" ||
			r.URL.Path == "/api/auth/refresh" || r.URL.Path == "/api/auth/logout" {
			next.ServeHTTP(w, r)
			return
		}
		gate := s.otaGate()
		if !gate.enter() {
			writeErr(w, http.StatusServiceUnavailable, dockerOTAMaintenanceMessage)
			return
		}
		defer gate.leave()
		next.ServeHTTP(w, r)
	})
}

func (d *dockerOTA) call(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	timeout := 30 * time.Second
	if path == "/v1/check" {
		timeout = 6 * time.Minute // bounded manifest/config reads plus signature verification
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://artex-updater"+path, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, errors.New("無法連線至 Docker 更新服務，請檢查主機上的 artex-updater")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 || resp.StatusCode < 200 || resp.StatusCode >= 500 ||
		(resp.StatusCode >= 300 && resp.StatusCode < 400) || !json.Valid(data) {
		return nil, 0, errors.New("Docker 更新服務回應無效；請重新讀取更新狀態")
	}
	return data, resp.StatusCode, nil
}

func writeDockerOTA(w http.ResponseWriter, data []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (s *Server) dockerOTAStatus(w http.ResponseWriter, r *http.Request) {
	if s.dockerOTA == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "active": false, "state": "idle", "message": "尚未設定 Docker OTA 更新服務"})
		return
	}
	data, status, err := s.dockerOTA.call(r.Context(), http.MethodGet, "/v1/status", nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var snapshot struct {
		Active *bool  `json:"active"`
		State  string `json:"state"`
	}
	if status == http.StatusOK && json.Unmarshal(data, &snapshot) == nil && snapshot.Active != nil && snapshot.State != "recovery_required" {
		s.dockerOTA.gate.reconcile(*snapshot.Active)
	}
	writeDockerOTA(w, data, status)
}

func decodeDockerOTA(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		writeErr(w, http.StatusBadRequest, "Docker OTA 請求格式錯誤")
		return false
	}
	return true
}

func (s *Server) dockerOTAConfigured(w http.ResponseWriter) bool {
	if s.dockerOTA == nil {
		writeErr(w, http.StatusServiceUnavailable, "尚未設定 Docker OTA 更新服務")
		return false
	}
	return true
}

func (s *Server) dockerOTACheck(w http.ResponseWriter, r *http.Request) {
	if !s.dockerOTAConfigured(w) {
		return
	}
	var input struct {
		Channel string `json:"channel"`
	}
	if !decodeDockerOTA(w, r, &input) {
		return
	}
	channel, err := selfupdate.ParseChannel(input.Channel)
	if err != nil || input.Channel == "" {
		writeErr(w, http.StatusBadRequest, "更新通道必須是 stable、nightly 或 main")
		return
	}
	data, status, err := s.dockerOTA.call(r.Context(), http.MethodPost, "/v1/check", map[string]any{"channel": channel})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeDockerOTA(w, data, status)
}

// The first OTA implementation requires an idle deployment. It does not claim
// to checkpoint arbitrary tools, pause user work, or resume live shell sessions.
func (s *Server) dockerOTAIdle() error {
	if s.m == nil || s.engine == nil {
		return errors.New("應用程式尚未就緒")
	}
	for _, task := range s.m.List() {
		state := task.lifecycleSnapshot()
		if (!state.Paused && !isTerminalStatus(state.Status)) || s.engine.inflightCount(task.ID) > 0 || s.engine.ActiveLLMCalls(task.ID) > 0 {
			return fmt.Errorf("任務 %s 尚未停止；請先暫停或完成所有任務", task.ID)
		}
	}
	s.chatMu.Lock()
	chatBusy := false
	for _, running := range s.chatBusy {
		chatBusy = chatBusy || running
	}
	s.chatMu.Unlock()
	s.queueMu.Lock()
	for _, active := range s.triggerActive {
		chatBusy = chatBusy || active > 0
	}
	for _, queued := range s.triggerQ {
		chatBusy = chatBusy || len(queued) > 0
	}
	s.queueMu.Unlock()
	if chatBusy {
		return errors.New("仍有 Agent 對話或觸發任務執行中，請等候完成")
	}
	if s.side != nil {
		s.side.mu.Lock()
		busy := len(s.side.runs) > 0
		s.side.mu.Unlock()
		if busy {
			return errors.New("仍有旁路問題執行中，請等候完成")
		}
	}
	return nil
}

func (s *Server) dockerOTAApply(w http.ResponseWriter, r *http.Request) {
	if !s.dockerOTAConfigured(w) {
		return
	}
	var input struct {
		PlanID string `json:"plan_id"`
	}
	if !decodeDockerOTA(w, r, &input) {
		return
	}
	if !dockerOTAPlanID.MatchString(input.PlanID) {
		writeErr(w, http.StatusBadRequest, "請先檢查更新並選擇有效的更新計畫")
		return
	}
	s.submitDockerOTA(w, r, "/v1/apply", input)
}

func (s *Server) dockerOTARollback(w http.ResponseWriter, r *http.Request) {
	if !s.dockerOTAConfigured(w) {
		return
	}
	var input struct{}
	if !decodeDockerOTA(w, r, &input) {
		return
	}
	s.submitDockerOTA(w, r, "/v1/rollback", input)
}

func (s *Server) submitDockerOTA(w http.ResponseWriter, r *http.Request, path string, input any) {
	gate := s.dockerOTA.gate
	if err := gate.begin(s.dockerOTAIdle); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	data, status, err := s.dockerOTA.call(r.Context(), http.MethodPost, path, input)
	if err != nil {
		gate.submissionFinished(true)
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if status >= 200 && status < 300 {
		marked, markerErr := gate.marker()
		if !marked || markerErr != nil {
			gate.submissionFinished(true)
			writeErr(w, http.StatusBadGateway, "更新服務未建立維護狀態，已暫停新操作；請檢查主機更新紀錄")
			return
		}
		log.Printf("[docker-ota] administrator submitted %s", path)
	}
	gate.submissionFinished(false)
	writeDockerOTA(w, data, status)
}

// Container-local readiness has its own Unix socket. It must not bypass the
// public anti-mapping gate, trust forwarding headers, or expose a TCP listener.
// StartDockerOTAReadiness is called only after main has initialized the public
// gate and successfully bound its HTTP listener.
func (s *Server) StartDockerOTAReadiness() error {
	if s.dockerOTA == nil {
		return nil
	}
	path := s.dockerOTA.healthSocket
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("Docker OTA readiness path is not a socket")
		}
		conn, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			_ = conn.Close()
			return errors.New("Docker OTA readiness socket is already in use")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return dialErr
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, current) {
			return errors.New("Docker OTA readiness socket changed during recovery")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.dockerOTAReadiness)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second}
	go func() {
		<-s.ctx.Done()
		_ = server.Close()
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[docker-ota] readiness listener: %v", err)
		}
	}()
	return nil
}

func (s *Server) dockerOTAReadiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	ready := s.m != nil && s.m.pg != nil && s.m.pg.PingContext(ctx) == nil
	dataDir := ""
	if s.m != nil {
		if absolute, err := filepath.Abs(s.m.dir); err == nil {
			dataDir, err = filepath.EvalSymlinks(absolute)
			if err != nil {
				ready = false
				dataDir = ""
			}
		} else {
			ready = false
		}
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	maintenance, idle := false, false
	if gate := s.otaGate(); gate != nil {
		gate.mu.Lock()
		marked, markerErr := gate.marker()
		maintenance = gate.pending || marked || markerErr != nil
		idle = markerErr == nil && gate.inflight == 0 && s.dockerOTAIdle() == nil
		gate.mu.Unlock()
	}
	writeJSON(w, status, map[string]any{
		"ready": ready, "maintenance": maintenance, "idle": idle, "ota_protocol": 1,
		"version": BuildVersion, "data_dir": dataDir, "gate_enabled": s.gate != nil,
	})
}
