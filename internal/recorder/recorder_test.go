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

// modelPage renders a model page the way Stripchat does: the numeric id sits in the
// preloaded state next to the username, whose case may differ from the wishlist.
func modelPage(id int64, username string) string {
	return fmt.Sprintf(`<html><script>window.__PRELOADED_STATE__ = {"viewCam":{"model":{"id":%d,"username":%q}},"other":{"id":7,"username":"someone"}};</script></html>`, id, username)
}

type fakeStripchat struct {
	*httptest.Server
	pages atomic.Int32
}

// newFakeStripchat serves /model as a model page with id 42 and the id-based cam
// endpoint through cam; the retired username endpoint answers 418 like the real site.
func newFakeStripchat(t *testing.T, cam http.HandlerFunc) *fakeStripchat {
	t.Helper()
	fake := &fakeStripchat{}
	fake.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/model":
			fake.pages.Add(1)
			fmt.Fprint(w, modelPage(42, "MoDeL"))
		case "/api/front/v2/models/42/cam":
			cam(w, request)
		case "/api/front/v2/models/username/model/cam":
			w.WriteHeader(http.StatusTeapot)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(fake.Close)
	return fake
}

func jsonReply(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
}

func TestCheckOnlineDecodesStructuredJSON(t *testing.T) {
	server := newFakeStripchat(t, jsonReply(`{"cam":{"isCamAvailable":true,"streamName":"stream-123"},"user":{"user":{"status":"public","username":"MoDeL"}}}`))
	r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
	info, err := r.CheckOnline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Available || info.StreamName != "stream-123" || info.Status != "public" {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestCheckOnlineTreatsEmptyCamArrayAsOffline(t *testing.T) {
	server := newFakeStripchat(t, jsonReply(`{"cam":[],"user":{"user":{"status":"off"}}}`))
	r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
	info, err := r.CheckOnline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Available || info.StreamName != "" || info.Status != "off" {
		t.Fatalf("unexpected offline info: %+v", info)
	}
}

func TestCheckOnlineClassifiesHTTPFailures(t *testing.T) {
	tests := []struct {
		code int
		kind string
	}{{404, "not_found"}, {403, "cloudflare_forbidden"}, {418, "blocked"}, {429, "rate_limited"}, {503, "server_error"}, {400, "http_error"}}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			server := newFakeStripchat(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(test.code) })
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
		case request.URL.Path == "/model":
			fmt.Fprint(w, modelPage(42, "model"))
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

// The retired username endpoint must never be relied on again: every check goes
// through the id-based endpoint, and the page is fetched once per model.
func TestCheckOnlineResolvesIDOnceAndUsesIDEndpoint(t *testing.T) {
	var camPaths []string
	server := newFakeStripchat(t, func(w http.ResponseWriter, request *http.Request) {
		camPaths = append(camPaths, request.URL.Path)
		jsonReply(`{"cam":[],"user":{"user":{"status":"off","username":"model"}}}`)(w, request)
	})
	r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
	for i := 0; i < 3; i++ {
		if _, err := r.CheckOnline(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if server.pages.Load() != 1 || len(camPaths) != 3 || camPaths[0] != "/api/front/v2/models/42/cam" {
		t.Fatalf("pages=%d cam=%v", server.pages.Load(), camPaths)
	}
}

// A 404 or a payload for someone else means the cached id is no longer this model's:
// it is dropped so the next check resolves it again.
func TestStaleModelIDIsResolvedAgain(t *testing.T) {
	for name, cam := range map[string]http.HandlerFunc{
		"not-found":  func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) },
		"other-user": jsonReply(`{"cam":[],"user":{"user":{"status":"off","username":"someone-else"}}}`),
	} {
		t.Run(name, func(t *testing.T) {
			server := newFakeStripchat(t, cam)
			r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
			for i := 0; i < 2; i++ {
				if _, err := r.CheckOnline(context.Background()); err == nil {
					t.Fatal("stale id accepted")
				}
			}
			if server.pages.Load() != 2 {
				t.Fatalf("page fetched %d times, want 2", server.pages.Load())
			}
		})
	}
}

// Stripchat redirects a name that is no longer a model to its user profile.
func TestFormerModelIsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/model" {
			http.Redirect(w, request, "/user/model", http.StatusFound)
			return
		}
		fmt.Fprint(w, `<html>profile</html>`)
	}))
	defer server.Close()
	r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
	_, err := r.CheckOnline(context.Background())
	var checkErr *CheckError
	if !errors.As(err, &checkErr) || checkErr.Kind != "not_found" {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestModelIDFromPageMatchesUsernameOnly(t *testing.T) {
	page := []byte(modelPage(218445934, "_ASUnyan"))
	if id := modelIDFromPage(page, "_asunyan"); id != 218445934 {
		t.Fatalf("id=%d", id)
	}
	if id := modelIDFromPage(page, "nobody"); id != 0 {
		t.Fatalf("id for absent model: %d", id)
	}
	if id := modelIDFromPage([]byte("<html>no state</html>"), "model"); id != 0 {
		t.Fatalf("id without state: %d", id)
	}
}

func TestDeletedModelReportsReason(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		fmt.Fprint(w, `<script>window.__PRELOADED_STATE__ = {"viewCamBase":{"error":{"type":"deletedPopular","model":{"username":"model"}}}};</script>`)
	}))
	defer server.Close()
	r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
	_, err := r.CheckOnline(context.Background())
	var checkErr *CheckError
	if !errors.As(err, &checkErr) || checkErr.Kind != "not_found" || !strings.Contains(err.Error(), "deletedPopular") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Stripchat sometimes serves the model page as a shell without the rendered state.
// That is retried and, if it persists, reported as transient, never as not_found.
func TestShellModelPageIsRetriedNotNotFound(t *testing.T) {
	modelPageRetryDelay = time.Millisecond
	for name, shells := range map[string]int32{"recovers": 2, "persists": 3} {
		t.Run(name, func(t *testing.T) {
			var pages atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/model":
					if pages.Add(1) <= shells {
						fmt.Fprint(w, `<html><script>window.__PRELOADED_STATE__ = {"config":{}};</script></html>`)
						return
					}
					fmt.Fprint(w, modelPage(42, "model"))
				case "/api/front/v2/models/42/cam":
					jsonReply(`{"cam":[],"user":{"user":{"status":"off","username":"model"}}}`)(w, request)
				}
			}))
			defer server.Close()
			r := NewWithOptions("model", Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
			_, err := r.CheckOnline(context.Background())
			var checkErr *CheckError
			if shells < modelPageAttempts {
				if err != nil || pages.Load() != shells+1 {
					t.Fatalf("shell pages not retried: err=%v pages=%d", err, pages.Load())
				}
			} else if !errors.As(err, &checkErr) || checkErr.Kind != "page_unavailable" || pages.Load() != modelPageAttempts {
				t.Fatalf("persistent shell misreported: err=%v pages=%d", err, pages.Load())
			}
		})
	}
}
