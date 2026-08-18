package recorder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mio/sc/internal/config"
	"github.com/mio/sc/internal/logger"
)

func TestCheckOnlineDecodesStructuredJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"cam":{"isCamAvailable":true,"streamName":"stream-123"},"user":{"user":{"status":"public"}}}`)
	}))
	defer server.Close()
	r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
	info, err := r.CheckOnline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Available || info.StreamName != "stream-123" || info.Status != "public" {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestCheckOnlineClassifiesHTTPFailures(t *testing.T) {
	tests := []struct {
		code int
		kind string
	}{{404, "not_found"}, {403, "cloudflare_forbidden"}, {429, "rate_limited"}, {503, "server_error"}}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) { w.WriteHeader(test.code) }))
			defer server.Close()
			r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
			_, err := r.CheckOnline(context.Background())
			var checkErr *CheckError
			if !errors.As(err, &checkErr) || checkErr.Kind != test.kind || checkErr.StatusCode != test.code {
				t.Fatalf("unexpected error: %#v", err)
			}
		})
	}
}

func TestProxyConfiguration(t *testing.T) {
	client, err := NewHTTPClient("http://proxy.example:3128")
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	proxyURL, err := transport.Proxy(&http.Request{URL: mustURL(t, "https://example.com")})
	if err != nil || proxyURL.String() != "http://proxy.example:3128" {
		t.Fatalf("HTTP proxy not applied: %v %v", proxyURL, err)
	}
	client, err = NewHTTPClient("socks5://127.0.0.1:1080")
	if err != nil || client.Transport.(*http.Transport).DialContext == nil {
		t.Fatalf("SOCKS5 proxy not applied: %v", err)
	}
	if _, err := NewHTTPClient("ftp://proxy.example"); err == nil {
		t.Fatal("unsupported proxy scheme was accepted")
	}
}

func TestContextCancellationStopsRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) { <-request.Context().Done() }))
	defer server.Close()
	r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := r.CheckOnline(ctx)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request did not preserve cancellation: %v", err)
	}
}

func TestNoDataHasFiniteRestarts(t *testing.T) {
	initRecorderConfig(t)
	var masters atomic.Int32
	server := newHLSServer(t, &masters, false)
	defer server.Close()
	r := NewWithOptions("model", Options{
		HTTPClient: server.Client(), APIBaseURL: server.URL, HLSBaseURL: server.URL + "/hls",
		FirstDataTimeout: 20 * time.Millisecond, NoDataTimeout: 20 * time.Millisecond,
		MaxNoDataRestarts: 1, PollInterval: 5 * time.Millisecond, RetryDelay: time.Millisecond,
	})
	r.Run(context.Background())
	snapshot := r.Snapshot()
	if snapshot.Restarts != 1 || !strings.Contains(snapshot.LastError, "no data") {
		t.Fatalf("unexpected restart snapshot: %+v", snapshot)
	}
	if masters.Load() != 2 {
		t.Fatalf("master requested %d times, want 2", masters.Load())
	}
}

func TestFileRotationMovesCompletedSegments(t *testing.T) {
	_, upDir := initRecorderConfig(t)
	t.Setenv("PATH", t.TempDir())
	var masters atomic.Int32
	server := newHLSServer(t, &masters, true)
	defer server.Close()
	r := NewWithOptions("model", Options{
		HTTPClient: server.Client(), APIBaseURL: server.URL, HLSBaseURL: server.URL + "/hls",
		FirstDataTimeout: 100 * time.Millisecond, NoDataTimeout: 100 * time.Millisecond,
		MaxNoDataRestarts: 1, PollInterval: 4 * time.Millisecond, RetryDelay: time.Millisecond,
		SegmentDuration: func() time.Duration { return 18 * time.Millisecond },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Millisecond)
	defer cancel()
	r.Run(ctx)
	files, err := filepath.Glob(filepath.Join(upDir, "model", "*.mp4"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatalf("got %d completed segments, want at least 2", len(files))
	}
}

func newHLSServer(t *testing.T, masters *atomic.Int32, withSegments bool) *httptest.Server {
	t.Helper()
	var sequence atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "/api/front/v2/models/"):
			fmt.Fprint(w, `{"cam":{"isCamAvailable":true,"streamName":"stream"},"user":{"user":{"status":"public"}}}`)
		case strings.HasSuffix(request.URL.Path, "/master/stream_auto.m3u8"):
			masters.Add(1)
			fmt.Fprint(w, "#EXTM3U\n#EXT-X-MOUFLON:PSCH:v1:Zeechoej4aleeshi\n#EXT-X-STREAM-INF:BANDWIDTH=1,RESOLUTION=1x1\nvariant.m3u8\n")
		case strings.HasSuffix(request.URL.Path, "/master/variant.m3u8"):
			if !withSegments {
				fmt.Fprint(w, "#EXTM3U\n")
				return
			}
			n := sequence.Add(1)
			fmt.Fprintf(w, "#EXTM3U\n#EXTINF:1,\n/segment/%d.m4s\n", n)
		case strings.HasPrefix(request.URL.Path, "/segment/"):
			_, _ = w.Write(make([]byte, 1500))
		default:
			http.NotFound(w, request)
		}
	}))
}

func initRecorderConfig(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.conf")
	content := "[paths]\nwishlist=./wanted.txt\nsave_directory=./captures\nup_directory=./up\nlog_directory=./logs\n[settings]\ncheckInterval=20\nsegmentDuration=30\n[web]\nhost=127.0.0.1\nport=18080\nbase_path=/sc\n"
	if err := os.WriteFile(configPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	config.Init(dir)
	if _, err := config.Load(configPath); err != nil {
		t.Fatal(err)
	}
	logger.Init(filepath.Join(dir, "logs"))
	return filepath.Join(dir, "captures"), filepath.Join(dir, "up")
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
