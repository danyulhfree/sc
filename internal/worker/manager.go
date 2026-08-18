package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/mio/sc/internal/logger"
	"github.com/mio/sc/internal/recorder"
	"github.com/mio/sc/internal/wishlist"
)

type RecordingInfo struct {
	Name           string    `json:"name"`
	File           string    `json:"file"`
	Bytes          int64     `json:"bytes"`
	ElapsedSeconds int64     `json:"elapsed_seconds"`
	StartedAt      time.Time `json:"started_at"`
	Restarts       int       `json:"restarts"`
	LastError      string    `json:"last_error,omitempty"`
}

type ModelInfo struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
	CheckedAt  time.Time `json:"checked_at,omitempty"`
	Paused     bool      `json:"paused"`
	Recording  bool      `json:"recording"`
}

type Snapshot struct {
	WantedCount   int             `json:"wanted_count"`
	CheckingCount int             `json:"checking_count"`
	Repeated      []string        `json:"repeated_models"`
	Recordings    []RecordingInfo `json:"recordings"`
	Models        []ModelInfo     `json:"models"`
}

type Manager struct {
	mu          sync.RWMutex
	store       *wishlist.Store
	recorders   map[string]*recorder.Recorder
	checking    map[string]bool
	wanted      map[string]bool
	paused      map[string]bool
	modelStatus map[string]recorder.ModelStatus
	repeated    []string
	stopped     bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewManager(store *wishlist.Store) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		store:       store,
		recorders:   make(map[string]*recorder.Recorder),
		checking:    make(map[string]bool),
		wanted:      make(map[string]bool),
		paused:      make(map[string]bool),
		modelStatus: make(map[string]recorder.ModelStatus),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	recordings := make([]RecordingInfo, 0, len(m.recorders))
	for model, active := range m.recorders {
		snapshot := active.Snapshot()
		if !snapshot.Online {
			continue
		}
		bytes := snapshot.Bytes
		if info, err := os.Stat(snapshot.File); err == nil {
			bytes = info.Size()
		}
		elapsed := int64(0)
		if !snapshot.RecordStartTime.IsZero() {
			elapsed = int64(now.Sub(snapshot.RecordStartTime).Seconds())
		}
		recordings = append(recordings, RecordingInfo{
			Name:           model,
			File:           filepath.Base(snapshot.File),
			Bytes:          bytes,
			ElapsedSeconds: elapsed,
			StartedAt:      snapshot.RecordStartTime.UTC(),
			Restarts:       snapshot.Restarts,
			LastError:      snapshot.LastError,
		})
	}
	sort.Slice(recordings, func(i, j int) bool { return recordings[i].Name < recordings[j].Name })

	models := make([]ModelInfo, 0, len(m.wanted))
	for model := range m.wanted {
		status := m.modelStatus[model]
		state := status.Status
		if state == "" {
			state = "pending"
		}
		if m.paused[model] {
			state = "paused"
		}
		_, recording := m.recorders[model]
		models = append(models, ModelInfo{
			Name:       model,
			Status:     state,
			Error:      status.Error,
			HTTPStatus: status.HTTPStatus,
			CheckedAt:  status.CheckedAt,
			Paused:     m.paused[model],
			Recording:  recording,
		})
	}
	sort.Slice(models, func(i, j int) bool { return models[i].Name < models[j].Name })

	repeated := append([]string(nil), m.repeated...)
	return Snapshot{
		WantedCount:   len(m.wanted),
		CheckingCount: len(m.checking),
		Repeated:      repeated,
		Recordings:    recordings,
		Models:        models,
	}
}

func (m *Manager) UpdateModels() error {
	models, repeated, err := m.store.Read()
	if err != nil {
		return fmt.Errorf("read wanted list: %w", err)
	}
	wanted := make(map[string]bool, len(models))
	for _, model := range models {
		wanted[model] = true
	}

	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return context.Canceled
	}
	m.wanted = wanted
	m.repeated = repeated
	for model, active := range m.recorders {
		if !wanted[model] {
			active.Stop()
			delete(m.paused, model)
			delete(m.modelStatus, model)
		}
	}
	for model := range m.paused {
		if !wanted[model] {
			delete(m.paused, model)
		}
	}
	toStart := make([]string, 0)
	for _, model := range models {
		_, active := m.recorders[model]
		if !active && !m.checking[model] && !m.paused[model] {
			m.checking[model] = true
			toStart = append(toStart, model)
		}
	}
	m.mu.Unlock()

	for _, model := range toStart {
		m.startRecorder(model)
	}
	return nil
}

func (m *Manager) Pause(model string) error {
	normalized, err := wishlist.Normalize(model)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return context.Canceled
	}
	if !m.wanted[normalized] {
		m.mu.Unlock()
		return wishlist.ErrNotFound
	}
	m.paused[normalized] = true
	active := m.recorders[normalized]
	m.mu.Unlock()
	if active != nil {
		active.Stop()
	}
	logger.Event("录制已暂停: %s", normalized)
	return nil
}

func (m *Manager) Resume(model string) error {
	normalized, err := wishlist.Normalize(model)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return context.Canceled
	}
	if !m.wanted[normalized] {
		m.mu.Unlock()
		return wishlist.ErrNotFound
	}
	if !m.paused[normalized] {
		m.mu.Unlock()
		return nil
	}
	delete(m.paused, normalized)
	_, active := m.recorders[normalized]
	checking := m.checking[normalized]
	if !active && !checking {
		m.checking[normalized] = true
	}
	m.mu.Unlock()
	if !active && !checking {
		m.startRecorder(normalized)
	}
	logger.Event("录制已恢复: %s", normalized)
	return nil
}

func (m *Manager) startRecorder(model string) {
	m.mu.Lock()
	if m.stopped {
		delete(m.checking, model)
		m.mu.Unlock()
		return
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Event("[PANIC] %s goroutine 崩溃: %v", model, recovered)
			}
			m.mu.Lock()
			delete(m.checking, model)
			m.mu.Unlock()
		}()

		active, err := recorder.New(model)
		if err != nil {
			m.setModelError(model, "configuration_error", err)
			return
		}
		active.SetStatusCallback(func(status recorder.ModelStatus) {
			m.mu.Lock()
			m.modelStatus[status.Model] = status
			m.mu.Unlock()
		})
		info, err := active.CheckOnline(m.ctx)
		if err != nil || !info.Available || info.Status != "public" {
			return
		}

		m.mu.Lock()
		if !m.wanted[model] || m.paused[model] || m.ctx.Err() != nil {
			m.mu.Unlock()
			return
		}
		m.recorders[model] = active
		delete(m.checking, model)
		m.mu.Unlock()

		active.Run(m.ctx)
		m.mu.Lock()
		if m.recorders[model] == active {
			delete(m.recorders, model)
		}
		m.mu.Unlock()
	}()
}

func (m *Manager) setModelError(model, kind string, err error) {
	m.mu.Lock()
	m.modelStatus[model] = recorder.ModelStatus{Model: model, Status: kind, Error: err.Error(), CheckedAt: time.Now().UTC()}
	m.mu.Unlock()
}

func (m *Manager) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	m.cancel()
	for _, active := range m.recorders {
		active.Stop()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func IsNotFound(err error) bool { return errors.Is(err, wishlist.ErrNotFound) }
