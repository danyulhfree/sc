package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/ini.v1"
)

// Snapshot is an immutable view of the runtime configuration.
type Snapshot struct {
	SaveDirectory   string
	Wishlist        string
	UpDirectory     string
	LogDirectory    string
	CheckInterval   int
	SegmentDuration int
	Proxy           string
	WebHost         string
	WebPort         int
	BasePath        string
}

// Config owns the single reloadable application configuration.
type Config struct {
	mu       sync.RWMutex
	path     string
	snapshot Snapshot
}

var (
	instance *Config
	mainDir  string
)

func MainDir() string { return mainDir }

func Init(dir string) {
	abs, err := filepath.Abs(dir)
	if err == nil {
		mainDir = abs
		return
	}
	mainDir = filepath.Clean(dir)
}

// Load initializes the process-wide Config. Reload never replaces this pointer.
func Load(path string) (*Config, error) {
	snapshot, err := parse(path)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c := &Config{path: abs, snapshot: snapshot}
	instance = c
	return c, nil
}

func Get() *Config { return instance }

func (c *Config) Reload() error {
	snapshot, err := parse(c.path)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.snapshot = snapshot
	c.mu.Unlock()
	return nil
}

func (c *Config) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snapshot
}

func (c *Config) Path() string { return c.path }

func (c *Config) GetSegmentDuration() int { return c.Snapshot().SegmentDuration }

// UpdateSegmentDuration persists the value before making it visible to readers.
func (c *Config) UpdateSegmentDuration(minutes int) error {
	if minutes < 1 || minutes > 24*60 {
		return fmt.Errorf("segment duration must be between 1 and 1440 minutes")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	iniFile, err := ini.Load(c.path)
	if err != nil {
		return err
	}
	iniFile.Section("settings").Key("segmentDuration").SetValue(strconv.Itoa(minutes))

	dir := filepath.Dir(c.path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	defer os.Remove(tmpPath)

	if err := iniFile.SaveTo(tmpPath); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, c.path); err != nil {
		return err
	}
	c.snapshot.SegmentDuration = minutes
	return nil
}

func parse(path string) (Snapshot, error) {
	iniFile, err := ini.Load(path)
	if err != nil {
		return Snapshot{}, err
	}

	baseDir := filepath.Dir(path)
	paths := iniFile.Section("paths")
	settings := iniFile.Section("settings")
	web := iniFile.Section("web")

	saveDir := normalizePath(baseDir, paths.Key("save_directory").MustString("./captures"))
	upDir := normalizePath(baseDir, paths.Key("up_directory").MustString(filepath.Join(filepath.Dir(saveDir), "up")))
	snapshot := Snapshot{
		SaveDirectory:   saveDir,
		Wishlist:        normalizePath(baseDir, paths.Key("wishlist").MustString("./wanted.txt")),
		UpDirectory:     upDir,
		LogDirectory:    normalizePath(baseDir, paths.Key("log_directory").MustString("./logs")),
		CheckInterval:   settings.Key("checkInterval").MustInt(20),
		SegmentDuration: settings.Key("segmentDuration").MustInt(30),
		Proxy:           strings.TrimSpace(settings.Key("proxy").String()),
		WebHost:         strings.TrimSpace(web.Key("host").MustString("127.0.0.1")),
		WebPort:         web.Key("port").MustInt(18080),
		BasePath:        normalizeBasePath(web.Key("base_path").MustString("/sc")),
	}
	if envProxy := strings.TrimSpace(os.Getenv("SC_PROXY")); envProxy != "" {
		snapshot.Proxy = envProxy
	}
	if snapshot.CheckInterval < 1 {
		snapshot.CheckInterval = 20
	}
	if snapshot.SegmentDuration < 1 || snapshot.SegmentDuration > 24*60 {
		snapshot.SegmentDuration = 30
	}
	if snapshot.WebHost != "127.0.0.1" && snapshot.WebHost != "localhost" {
		return Snapshot{}, fmt.Errorf("web.host must be localhost")
	}
	if snapshot.WebPort < 1 || snapshot.WebPort > 65535 {
		return Snapshot{}, fmt.Errorf("invalid web.port %d", snapshot.WebPort)
	}

	for _, dir := range []string{snapshot.SaveDirectory, snapshot.UpDirectory, snapshot.LogDirectory} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Snapshot{}, fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return snapshot, nil
}

func normalizePath(baseDir, path string) string {
	path = os.ExpandEnv(strings.TrimSpace(path))
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

func normalizeBasePath(path string) string {
	path = "/" + strings.Trim(strings.TrimSpace(path), "/")
	if path == "/" {
		return ""
	}
	return path
}

func ParseInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
