package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mio/sc/internal/api"
	"github.com/mio/sc/internal/config"
	"github.com/mio/sc/internal/logger"
	"github.com/mio/sc/internal/mouflon"
	"github.com/mio/sc/internal/recorder"
	"github.com/mio/sc/internal/wishlist"
	"github.com/mio/sc/internal/worker"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sc:", err)
		os.Exit(1)
	}
}

func run() error {
	mainDir, err := applicationDir()
	if err != nil {
		return err
	}
	configPath := flag.String("config", filepath.Join(mainDir, "config.conf"), "path to config.conf")
	templatesDir := flag.String("templates", filepath.Join(mainDir, "templates"), "path to HTML templates")
	keysDir := flag.String("keys-dir", mainDir, "directory containing stripchat_mouflon_keys.json")
	flag.Parse()

	config.Init(mainDir)
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	snapshot := cfg.Snapshot()
	logger.Init(snapshot.LogDirectory)
	mouflon.Init(*keysDir)
	logger.Event("配置加载完毕: %s", cfg.Path())

	if err := processExistingCaptures(snapshot); err != nil {
		logger.Event("处理遗留录制文件失败: %v", err)
	}
	store := wishlist.New(snapshot.Wishlist)
	manager := worker.NewManager(store)
	if err := manager.UpdateModels(); err != nil {
		return err
	}

	startedAt := time.Now().UTC()
	webServer, err := api.NewServer(manager, store, cfg, api.Options{TemplatesDir: *templatesDir, Version: version, StartedAt: startedAt})
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- webServer.Start(ctx) }()

	logger.Event("StripchatRecorder (Go) %s 已启动", version)
	fmt.Printf("SC %s 已启动，监听 http://%s:%d%s/\n", version, snapshot.WebHost, snapshot.WebPort, snapshot.BasePath)
	timer := time.NewTimer(time.Duration(snapshot.CheckInterval) * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Event("收到退出指令，正在关闭")
			manager.Stop()
			select {
			case err := <-serverErrors:
				if err != nil {
					return err
				}
			case <-time.After(10 * time.Second):
				return errors.New("web server shutdown timed out")
			}
			return nil
		case err := <-serverErrors:
			manager.Stop()
			if err == nil {
				return errors.New("web server stopped unexpectedly")
			}
			return err
		case <-timer.C:
			if err := cfg.Reload(); err != nil {
				logger.Event("配置重载失败，继续使用旧快照: %v", err)
			} else {
				mouflon.LoadKeys()
			}
			if err := manager.UpdateModels(); err != nil {
				logger.Event("更新 wanted 列表失败: %v", err)
			}
			current := cfg.Snapshot()
			printStatus(manager.Snapshot(), current.CheckInterval)
			timer.Reset(time.Duration(current.CheckInterval) * time.Second)
		}
	}
}

func applicationDir() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(executable)
	if _, err := os.Stat(filepath.Join(dir, "config.conf")); err == nil {
		return dir, nil
	}
	return os.Getwd()
}

func processExistingCaptures(snapshot config.Snapshot) error {
	entries, err := os.ReadDir(snapshot.SaveDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		model := entry.Name()
		files, err := filepath.Glob(filepath.Join(snapshot.SaveDirectory, model, "*.mp4"))
		if err != nil {
			return err
		}
		for _, file := range files {
			if err := recorder.ProcessCompletedFile(file, model); err != nil {
				logger.Event("遗留文件处理失败 %s: %v", file, err)
			}
		}
	}
	return nil
}

func printStatus(snapshot worker.Snapshot, interval int) {
	fmt.Printf("检查中 %d，wanted %d，录制中 %d；下次检查 %d 秒后\n", snapshot.CheckingCount, snapshot.WantedCount, len(snapshot.Recordings), interval)
}
