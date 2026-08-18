package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	logPath string
	logMu   sync.Mutex
)

// Init 初始化日志模块
func Init(logDir string) {
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[LOG ERROR] %v\n", err)
	}
	logPath = filepath.Join(logDir, "sc.log")
}

// Event 记录事件日志（线程安全）
func Event(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}

	timestamp := time.Now().Format("02/01/2006 15:04:05")
	line := fmt.Sprintf("\n%s %s\n", timestamp, msg)

	logMu.Lock()
	defer logMu.Unlock()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[LOG ERROR] %v\n", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		fmt.Fprintf(os.Stderr, "[LOG ERROR] %v\n", err)
	}
}

// Info 输出到控制台并记录日志
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(msg)
	Event("%s", msg)
}

// Debug 仅输出到控制台
func Debug(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
