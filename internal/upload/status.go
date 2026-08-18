package upload

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxStatusSize = 1 << 20

type Result struct {
	Path    string    `json:"path,omitempty"`
	Bytes   int64     `json:"bytes,omitempty"`
	Message string    `json:"message,omitempty"`
	Code    int       `json:"code,omitempty"`
	At      time.Time `json:"at,omitempty"`
}

type Status struct {
	Version     int       `json:"version"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	State       string    `json:"state"`
	QueueFiles  int       `json:"queue_files"`
	QueueBytes  int64     `json:"queue_bytes"`
	LastSuccess *Result   `json:"last_success,omitempty"`
	LastError   *Result   `json:"last_error,omitempty"`
}

func Read(queueDir, statusPath string) Status {
	status := Status{Version: 1, State: "idle"}
	if file, err := os.Open(statusPath); err == nil {
		defer file.Close()
		if info, statErr := file.Stat(); statErr == nil && info.Size() <= maxStatusSize {
			_ = json.NewDecoder(file).Decode(&status)
		}
	}
	status.QueueFiles, status.QueueBytes = scanQueue(queueDir)
	if status.State == "" {
		status.State = "idle"
	}
	return status
}

func scanQueue(root string) (int, int64) {
	files := 0
	var bytes int64
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type().IsRegular() && strings.EqualFold(filepath.Ext(entry.Name()), ".mp4") {
			if info, infoErr := entry.Info(); infoErr == nil {
				files++
				bytes += info.Size()
			}
		}
		return nil
	})
	return files, bytes
}
