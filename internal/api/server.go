package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mio/sc/internal/config"
	"github.com/mio/sc/internal/logger"
	"github.com/mio/sc/internal/upload"
	"github.com/mio/sc/internal/wishlist"
	"github.com/mio/sc/internal/worker"
)

type DiskStatus struct {
	TotalBytes int64 `json:"total_bytes"`
	UsedBytes  int64 `json:"used_bytes"`
	FreeBytes  int64 `json:"free_bytes"`
	UsedPct    int   `json:"used_percent"`
}

type StatusResponse struct {
	App struct {
		Version   string    `json:"version"`
		StartedAt time.Time `json:"started_at"`
		UptimeSec int64     `json:"uptime_seconds"`
	} `json:"app"`
	Manager        worker.Snapshot `json:"manager"`
	Disk           DiskStatus      `json:"disk"`
	Upload         upload.Status   `json:"upload"`
	SegmentMinutes int             `json:"segment_minutes"`
}

type Options struct {
	TemplatesDir string
	Version      string
	StartedAt    time.Time
}

type Server struct {
	engine    *gin.Engine
	manager   *worker.Manager
	store     *wishlist.Store
	config    *config.Config
	csrfToken string
	version   string
	startedAt time.Time
	http      *http.Server
}

func NewServer(manager *worker.Manager, store *wishlist.Store, cfg *config.Config, opts Options) (*Server, error) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	if opts.StartedAt.IsZero() {
		opts.StartedAt = time.Now().UTC()
	}
	server := &Server{
		engine:    engine,
		manager:   manager,
		store:     store,
		config:    cfg,
		csrfToken: token,
		version:   opts.Version,
		startedAt: opts.StartedAt,
	}
	if err := server.setupRoutes(opts.TemplatesDir); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.engine }

func (s *Server) Start(ctx context.Context) error {
	snapshot := s.config.Snapshot()
	address := net.JoinHostPort(snapshot.WebHost, fmt.Sprintf("%d", snapshot.WebPort))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen %s: %w", address, err)
	}
	s.http = &http.Server{Handler: s.engine, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	logger.Event("[Web服务] 监听 http://%s%s/", address, snapshot.BasePath)

	shutdownDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.http.Shutdown(shutdownCtx)
		case <-shutdownDone:
		}
	}()
	err = s.http.Serve(listener)
	close(shutdownDone)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) setupRoutes(templatesDir string) error {
	if templatesDir == "" {
		templatesDir = filepath.Join(config.MainDir(), "templates")
	}
	templates, err := template.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}
	s.engine.SetHTMLTemplate(templates)
	s.engine.GET("/healthz", s.healthzHandler)

	basePath := s.config.Snapshot().BasePath
	group := s.engine.Group(basePath)
	group.GET("/", s.indexHandler)
	group.Static("/static", filepath.Join(filepath.Dir(templatesDir), "static"))
	group.GET("/wanted", s.wantedPageHandler)
	group.GET("/api/health", s.healthHandler)
	group.GET("/api/status", s.statusHandler)
	group.GET("/api/wanted", s.getWantedHandler)

	writes := group.Group("")
	writes.Use(s.csrfMiddleware())
	writes.POST("/api/wanted", s.addWantedHandler)
	writes.DELETE("/api/wanted/:model", s.deleteWantedHandler)
	writes.PUT("/api/settings/segment-duration", s.segmentDurationHandler)
	writes.POST("/api/models/:model/pause", s.pauseHandler)
	writes.POST("/api/models/:model/resume", s.resumeHandler)
	return nil
}

func (s *Server) csrfMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		provided := ctx.GetHeader("X-CSRF-Token")
		if len(provided) != len(s.csrfToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.csrfToken)) != 1 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid CSRF token"})
			return
		}
		ctx.Next()
	}
}

func (s *Server) pageData() gin.H {
	snapshot := s.config.Snapshot()
	return gin.H{"base_path": snapshot.BasePath, "csrf_token": s.csrfToken, "segment_minutes": snapshot.SegmentDuration}
}

func (s *Server) indexHandler(ctx *gin.Context) { ctx.HTML(http.StatusOK, "index.html", s.pageData()) }
func (s *Server) wantedPageHandler(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "edit_wanted.html", s.pageData())
}

func (s *Server) healthzHandler(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "version": s.version})
}

func (s *Server) healthHandler(ctx *gin.Context) {
	snapshot := s.config.Snapshot()
	_, ffmpegErr := exec.LookPath("ffmpeg")
	_, _, wantedErr := s.store.Read()
	statusPath := filepath.Join(snapshot.LogDirectory, "uploader_status.json")
	_, statusErr := os.Stat(statusPath)
	ctx.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"version":    s.version,
		"started_at": s.startedAt,
		"dependencies": gin.H{
			"ffmpeg":          dependencyState(ffmpegErr),
			"wanted":          dependencyState(wantedErr),
			"uploader_status": dependencyState(statusErr),
		},
	})
}

func (s *Server) statusHandler(ctx *gin.Context) {
	snapshot := s.config.Snapshot()
	response := StatusResponse{
		Manager:        s.manager.Snapshot(),
		Disk:           diskUsage(snapshot.SaveDirectory),
		Upload:         upload.Read(snapshot.UpDirectory, filepath.Join(snapshot.LogDirectory, "uploader_status.json")),
		SegmentMinutes: snapshot.SegmentDuration,
	}
	response.App.Version = s.version
	response.App.StartedAt = s.startedAt
	response.App.UptimeSec = int64(time.Since(s.startedAt).Seconds())
	ctx.JSON(http.StatusOK, response)
}

func (s *Server) getWantedHandler(ctx *gin.Context) {
	models, repeated, err := s.store.Read()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"models": models, "repeated_models": repeated})
}

func (s *Server) addWantedHandler(ctx *gin.Context) {
	var request struct {
		Model  string   `json:"model"`
		Models []string `json:"models"`
	}
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	models := request.Models
	if strings.TrimSpace(request.Model) != "" {
		models = append(models, request.Model)
	}
	added, err := s.store.Add(models)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.manager.UpdateModels(); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	logger.Event("API 添加 wanted: %v", added)
	ctx.JSON(http.StatusOK, gin.H{"added": added})
}

func (s *Server) deleteWantedHandler(ctx *gin.Context) {
	model := ctx.Param("model")
	if err := s.store.Delete(model); err != nil {
		if errors.Is(err, wishlist.ErrNotFound) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	if err := s.manager.UpdateModels(); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	logger.Event("API 删除 wanted: %s", model)
	ctx.JSON(http.StatusOK, gin.H{"deleted": strings.ToLower(model)})
}

func (s *Server) segmentDurationHandler(ctx *gin.Context) {
	var request struct {
		Minutes int `json:"minutes"`
	}
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	if err := s.config.UpdateSegmentDuration(request.Minutes); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.Event("分段录制时长已更新为 %d 分钟", request.Minutes)
	ctx.JSON(http.StatusOK, gin.H{"minutes": request.Minutes})
}

func (s *Server) pauseHandler(ctx *gin.Context) {
	if err := s.manager.Pause(ctx.Param("model")); err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"paused": true})
}

func (s *Server) resumeHandler(ctx *gin.Context) {
	if err := s.manager.Resume(ctx.Param("model")); err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"paused": false})
}

func writeManagerError(ctx *gin.Context, err error) {
	status := http.StatusBadRequest
	if worker.IsNotFound(err) {
		status = http.StatusNotFound
	}
	ctx.JSON(status, gin.H{"error": err.Error()})
}

func dependencyState(err error) gin.H {
	if err == nil {
		return gin.H{"ok": true}
	}
	return gin.H{"ok": false, "error": err.Error()}
}

func diskUsage(path string) DiskStatus {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return DiskStatus{}
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bavail) * int64(stat.Bsize)
	used := total - free
	percent := 0
	if total > 0 {
		percent = int(used * 100 / total)
	}
	return DiskStatus{TotalBytes: total, UsedBytes: used, FreeBytes: free, UsedPct: percent}
}

func randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
