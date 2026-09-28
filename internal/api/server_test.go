package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mio/sc/internal/config"
	"github.com/mio/sc/internal/wishlist"
	"github.com/mio/sc/internal/worker"
)

func TestBasePathCSRFAndRoutes(t *testing.T) {
	server, manager, cfg := newTestServer(t)
	defer manager.Stop()

	assertStatus(t, server, http.MethodGet, "/api/status", nil, "", http.StatusNotFound)
	assertStatus(t, server, http.MethodGet, "/healthz", nil, "", http.StatusOK)
	assertStatus(t, server, http.MethodGet, "/sc/api/health", nil, "", http.StatusOK)
	assertStatus(t, server, http.MethodGet, "/sc/api/status", nil, "", http.StatusOK)
	assertStatus(t, server, http.MethodGet, "/sc/", nil, "", http.StatusOK)
	assertStatus(t, server, http.MethodGet, "/sc/wanted", nil, "", http.StatusOK)
	for _, asset := range []string{"jp-ui.css", "jp-ui.js", "sc.css", "sc.js", "wanted.js"} {
		assertStatus(t, server, http.MethodGet, "/sc/static/"+asset, nil, "", http.StatusOK)
	}
	assertStatus(t, server, http.MethodGet, "/sc/static/", nil, "", http.StatusNotFound)

	assertStatus(t, server, http.MethodPut, "/sc/api/settings/segment-duration", map[string]any{"minutes": 12}, "", http.StatusForbidden)
	assertStatus(t, server, http.MethodPost, "/sc/api/wanted", map[string]any{"model": "../escape"}, server.csrfToken, http.StatusBadRequest)
	assertStatus(t, server, http.MethodPut, "/sc/api/settings/segment-duration", map[string]any{"minutes": 12}, server.csrfToken, http.StatusOK)
	if cfg.Snapshot().SegmentDuration != 12 {
		t.Fatal("segment duration was not updated")
	}
	data, err := os.ReadFile(cfg.Path())
	if err != nil || !strings.Contains(string(data), "segmentDuration = 12") {
		t.Fatalf("segment duration not persisted: %v %s", err, data)
	}
}

func TestWantedPauseResumeLifecycle(t *testing.T) {
	server, manager, _ := newTestServer(t)
	defer manager.Stop()

	assertStatus(t, server, http.MethodPost, "/sc/api/models/alpha/pause", nil, server.csrfToken, http.StatusOK)
	snapshot := manager.Snapshot()
	if len(snapshot.Models) != 1 || !snapshot.Models[0].Paused {
		t.Fatalf("model was not paused: %+v", snapshot.Models)
	}
	assertStatus(t, server, http.MethodPost, "/sc/api/models/alpha/resume", nil, server.csrfToken, http.StatusOK)
	if manager.Snapshot().Models[0].Paused {
		t.Fatal("model was not resumed")
	}
	assertStatus(t, server, http.MethodPost, "/sc/api/wanted", map[string]any{"models": []string{"beta", "gamma"}}, server.csrfToken, http.StatusOK)
	assertStatus(t, server, http.MethodDelete, "/sc/api/wanted/beta", nil, server.csrfToken, http.StatusOK)

	request := httptest.NewRequest(http.MethodGet, "/sc/api/wanted", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var body struct {
		Models []string `json:"models"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if strings.Join(body.Models, ",") != "alpha,gamma" {
		t.Fatalf("unexpected wanted list: %v", body.Models)
	}
}

func newTestServer(t *testing.T) (*Server, *worker.Manager, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.conf")
	content := "[paths]\nwishlist=./wanted.txt\nsave_directory=./captures\nup_directory=./up\nlog_directory=./logs\n[settings]\ncheckInterval=20\nsegmentDuration=30\n[web]\nhost=127.0.0.1\nport=18080\nbase_path=/sc\n"
	if err := os.WriteFile(configPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wanted.txt"), []byte("alpha\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	config.Init(dir)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	store := wishlist.New(filepath.Join(dir, "wanted.txt"))
	manager := worker.NewManager(store)
	if err := manager.UpdateModels(); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(manager, store, cfg, Options{TemplatesDir: filepath.Join("..", "..", "templates"), Version: "test"})
	if err != nil {
		manager.Stop()
		t.Fatal(err)
	}
	return server, manager, cfg
}

func assertStatus(t *testing.T, server *Server, method, path string, body any, csrf string, expected int) {
	t.Helper()
	var requestBody *bytes.Reader
	if body == nil {
		requestBody = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		requestBody = bytes.NewReader(data)
	}
	request := httptest.NewRequest(method, path, requestBody)
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != expected {
		t.Fatalf("%s %s: got %d, want %d; body=%s", method, path, response.Code, expected, response.Body.String())
	}
}
