package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReloadKeepsGlobalInstanceAndPersistsSegmentDuration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	writeConfig := func(interval, segment string) {
		t.Helper()
		content := "[paths]\nwishlist = ./wanted.txt\nsave_directory = ./captures\nup_directory = ./up\nlog_directory = ./logs\n\n[settings]\ncheckInterval = " + interval + "\nsegmentDuration = " + segment + "\n\n[web]\nhost = 127.0.0.1\nport = 18080\nbase_path = /sc/\n"
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig("20", "30")
	Init(dir)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	pointer := Get()
	writeConfig("7", "45")
	if err := cfg.Reload(); err != nil {
		t.Fatal(err)
	}
	if Get() != pointer {
		t.Fatal("Reload replaced the global Config pointer")
	}
	snapshot := cfg.Snapshot()
	if snapshot.CheckInterval != 7 || snapshot.SegmentDuration != 45 || snapshot.BasePath != "/sc" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if err := cfg.UpdateSegmentDuration(12); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "segmentDuration = 12") {
		t.Fatalf("segment duration was not persisted:\n%s", data)
	}
	if cfg.Snapshot().SegmentDuration != 12 {
		t.Fatal("persisted value is not visible in the snapshot")
	}
}

func TestRejectsNonLocalWebHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	content := "[paths]\n\n[settings]\n\n[web]\nhost = 0.0.0.0\nport = 18080\nbase_path = /sc\n"
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	Init(dir)
	if _, err := Load(path); err == nil {
		t.Fatal("expected non-local host to be rejected")
	}
}
