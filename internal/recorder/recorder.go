package recorder

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mio/sc/internal/config"
	"github.com/mio/sc/internal/hls"
	"github.com/mio/sc/internal/logger"
	"github.com/mio/sc/internal/mouflon"
	"golang.org/x/net/proxy"
)

const (
	minFileSize       = 1024
	onlineCheckPeriod = 30 * time.Second
	requestBodyLimit  = 8 << 20
)

var errNoData = errors.New("stream produced no data")

const modelPageAttempts = 3

var modelPageRetryDelay = time.Second

// The model page embeds its initial state as JSON; the model's numeric id is taken
// from the object whose username matches, which the page renders for any visitor.
var preloadedStatePattern = regexp.MustCompile(`(?s)window\.__PRELOADED_STATE__\s*=\s*(\{.*?\})\s*;?\s*</script>`)

var DefaultHeaders = map[string]string{
	"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Accept":          "application/x-mpegURL,application/vnd.apple.mpegurl,application/json,text/xml,text/html,application/xhtml+xml,image/webp,text/plain,*/*;q=0.8",
	"Accept-Language": "en-US,en;q=0.5",
	"Origin":          "https://stripchat.com",
	"Referer":         "https://stripchat.com/",
	"Sec-Fetch-Dest":  "empty",
	"Sec-Fetch-Mode":  "cors",
	"Sec-Fetch-Site":  "cross-site",
	"Pragma":          "no-cache",
	"Cache-Control":   "no-cache",
}

type CheckError struct {
	Kind       string `json:"kind"`
	StatusCode int    `json:"status_code,omitempty"`
	Err        error  `json:"-"`
}

func (e *CheckError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Kind, e.Err)
	}
	return e.Kind
}

func (e *CheckError) Unwrap() error { return e.Err }

type OnlineInfo struct {
	Available  bool
	StreamName string
	Status     string
}

type ModelStatus struct {
	Model      string    `json:"model"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
}

type Snapshot struct {
	Model           string    `json:"model"`
	File            string    `json:"file"`
	Online          bool      `json:"online"`
	Status          string    `json:"status"`
	RecordStartTime time.Time `json:"record_start_time"`
	SegmentStart    time.Time `json:"segment_start"`
	Bytes           int64     `json:"bytes"`
	Restarts        int       `json:"restarts"`
	LastError       string    `json:"last_error,omitempty"`
	Stopped         bool      `json:"stopped"`
}

type Options struct {
	HTTPClient        *http.Client
	APIBaseURL        string
	HLSBaseURL        string
	FirstDataTimeout  time.Duration
	NoDataTimeout     time.Duration
	MaxNoDataRestarts int
	PollInterval      time.Duration
	RetryDelay        time.Duration
	SegmentDuration   func() time.Duration
}

type Recorder struct {
	mu               sync.RWMutex
	model            string
	file             string
	online           bool
	status           string
	streamName       string
	recordStartTime  time.Time
	segmentStart     time.Time
	bytes            int64
	restarts         int
	lastError        string
	stopped          bool
	stopOnce         sync.Once
	stopChan         chan struct{}
	httpClient       *http.Client
	apiBaseURL       string
	hlsBaseURL       string
	modelID          int64
	firstDataTimeout time.Duration
	noDataTimeout    time.Duration
	maxRestarts      int
	pollInterval     time.Duration
	retryDelay       time.Duration
	segmentDuration  func() time.Duration
	onStatusChange   func(ModelStatus)
}

func New(model string) (*Recorder, error) {
	client, err := NewHTTPClient(config.Get().Snapshot().Proxy)
	if err != nil {
		return nil, err
	}
	return NewWithOptions(model, Options{HTTPClient: client}), nil
}

func NewWithOptions(model string, opts Options) *Recorder {
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.APIBaseURL == "" {
		opts.APIBaseURL = "https://stripchat.com"
	}
	if opts.HLSBaseURL == "" {
		opts.HLSBaseURL = "https://edge-hls.doppiocdn.com/hls"
	}
	if opts.FirstDataTimeout <= 0 {
		opts.FirstDataTimeout = 20 * time.Second
	}
	if opts.NoDataTimeout <= 0 {
		opts.NoDataTimeout = 45 * time.Second
	}
	if opts.MaxNoDataRestarts < 1 {
		opts.MaxNoDataRestarts = 3
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 500 * time.Millisecond
	}
	if opts.RetryDelay <= 0 {
		opts.RetryDelay = 2 * time.Second
	}
	if opts.SegmentDuration == nil {
		opts.SegmentDuration = func() time.Duration {
			return time.Duration(config.Get().Snapshot().SegmentDuration) * time.Minute
		}
	}
	return &Recorder{
		model:            model,
		stopChan:         make(chan struct{}),
		httpClient:       opts.HTTPClient,
		apiBaseURL:       strings.TrimRight(opts.APIBaseURL, "/"),
		hlsBaseURL:       strings.TrimRight(opts.HLSBaseURL, "/"),
		firstDataTimeout: opts.FirstDataTimeout,
		noDataTimeout:    opts.NoDataTimeout,
		maxRestarts:      opts.MaxNoDataRestarts,
		pollInterval:     opts.PollInterval,
		retryDelay:       opts.RetryDelay,
		segmentDuration:  opts.SegmentDuration,
	}
}

func NewHTTPClient(proxyURL string) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("parse proxy: %w", err)
		}
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https":
			transport.Proxy = http.ProxyURL(parsed)
		case "socks5", "socks5h":
			var auth *proxy.Auth
			if parsed.User != nil {
				password, _ := parsed.User.Password()
				auth = &proxy.Auth{User: parsed.User.Username(), Password: password}
			}
			dialer, err := proxy.SOCKS5("tcp", parsed.Host, auth, &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second})
			if err != nil {
				return nil, fmt.Errorf("configure socks5 proxy: %w", err)
			}
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				transport.DialContext = contextDialer.DialContext
			} else {
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					type result struct {
						conn net.Conn
						err  error
					}
					resultCh := make(chan result, 1)
					go func() {
						conn, err := dialer.Dial(network, address)
						resultCh <- result{conn: conn, err: err}
					}()
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case value := <-resultCh:
						return value.conn, value.err
					}
				}
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
		}
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func (r *Recorder) SetStatusCallback(callback func(ModelStatus)) {
	r.mu.Lock()
	r.onStatusChange = callback
	r.mu.Unlock()
}

func (r *Recorder) Stop() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.stopped = true
		r.mu.Unlock()
		close(r.stopChan)
	})
}

func (r *Recorder) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Snapshot{
		Model:           r.model,
		File:            r.file,
		Online:          r.online,
		Status:          r.status,
		RecordStartTime: r.recordStartTime,
		SegmentStart:    r.segmentStart,
		Bytes:           r.bytes,
		Restarts:        r.restarts,
		LastError:       r.lastError,
		Stopped:         r.stopped,
	}
}

func (r *Recorder) Run(ctx context.Context) {
	for attempt := 0; ; attempt++ {
		err := r.recordOnce(ctx)
		if err == nil || !errors.Is(err, errNoData) || ctx.Err() != nil || r.isStopped() {
			if err != nil && !errors.Is(err, context.Canceled) {
				r.setError(err)
			}
			return
		}
		if attempt >= r.maxRestarts {
			r.setError(err)
			return
		}
		r.mu.Lock()
		r.restarts++
		r.lastError = err.Error()
		r.mu.Unlock()
		logger.Event("[%s] 无数据，重启录制 (%d/%d)", r.model, attempt+1, r.maxRestarts)
		if !waitContext(ctx, r.stopChan, r.retryDelay) {
			return
		}
	}
}

func (r *Recorder) recordOnce(ctx context.Context) error {
	info, err := r.CheckOnline(ctx)
	if err != nil || !info.Available || info.Status != "public" {
		return err
	}

	masterURL := fmt.Sprintf("%s/%s/master/%s_auto.m3u8", r.hlsBaseURL, info.StreamName, info.StreamName)
	masterBody, err := r.getBody(ctx, masterURL)
	if err != nil {
		return fmt.Errorf("master playlist: %w", err)
	}
	pkeys := hls.GetMouflonPKeys(string(masterBody))
	if len(pkeys) == 0 {
		return errors.New("master playlist has no MOUFLON keys")
	}
	best := hls.PickBestVariant(hls.ParseMaster(string(masterBody), masterURL))
	if best == nil || best.URL == "" {
		return errors.New("master playlist has no usable variant")
	}

	for _, pair := range pkeys {
		for _, decryptKey := range mouflon.GetDecryptKey(pair.Pkey) {
			if pair.Psch == "v2" && !r.probeKey(ctx, best.URL, pair.Psch, pair.Pkey, decryptKey) {
				continue
			}
			if err := r.capture(ctx, info.StreamName, best.URL, pair.Psch, pair.Pkey, decryptKey); err != nil {
				return err
			}
			return nil
		}
	}
	return errors.New("no valid MOUFLON decryption key")
}

func (r *Recorder) probeKey(ctx context.Context, variantURL, psch, pkey, decryptKey string) bool {
	authURL := mouflon.AppendAuthParams(variantURL, psch, pkey, decryptKey)
	body, err := r.getBody(ctx, authURL)
	if err != nil || hls.IsAdPlaylist(string(body)) {
		return false
	}
	if psch != "v2" {
		return true
	}
	segments, _ := hls.BuildMouflonSegmentURLs(string(body), hls.GetBaseURL(variantURL), psch, pkey, decryptKey)
	for _, segment := range segments {
		segmentURL := mouflon.AppendAuthParams(segment.URL, psch, pkey, decryptKey)
		if _, err := r.getBody(ctx, segmentURL); err == nil {
			return true
		}
	}
	return false
}

func (r *Recorder) capture(ctx context.Context, streamName, variantURL, psch, pkey, decryptKey string) error {
	if err := os.MkdirAll(filepath.Join(config.Get().Snapshot().SaveDirectory, r.model), 0o755); err != nil {
		return err
	}
	authURL := mouflon.AppendAuthParams(variantURL, psch, pkey, decryptKey)
	seen := make(map[string]bool)
	started := time.Now()
	lastData := started
	lastOnlineCheck := started
	mediaReceived := false
	initDownloaded := false

	file, err := r.openSegment()
	if err != nil {
		return err
	}
	currentPath := r.Snapshot().File
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	logger.Event("开始 MOUFLON 录制: %s -> %s", r.model, currentPath)
	for {
		if !waitContext(ctx, r.stopChan, 0) {
			return r.finishSegment(file, currentPath, "最终")
		}
		now := time.Now()
		if !mediaReceived && now.Sub(started) >= r.firstDataTimeout {
			_ = r.finishSegment(file, currentPath, "超时")
			file = nil
			return errNoData
		}
		if mediaReceived && now.Sub(lastData) >= r.noDataTimeout {
			_ = r.finishSegment(file, currentPath, "无数据")
			file = nil
			return errNoData
		}

		if now.Sub(lastOnlineCheck) >= onlineCheckPeriod {
			info, checkErr := r.CheckOnline(ctx)
			if checkErr != nil {
				logger.Event("[%s] 在线检查失败: %v", r.model, checkErr)
			} else if !info.Available || info.Status != "public" {
				return r.finishSegment(file, currentPath, "最终")
			}
			lastOnlineCheck = now
		}

		segmentDuration := r.segmentDuration()
		if segmentDuration > 0 && now.Sub(r.Snapshot().SegmentStart) >= segmentDuration {
			if err := r.finishSegment(file, currentPath, "分段"); err != nil {
				return err
			}
			file, err = r.openSegment()
			if err != nil {
				return err
			}
			currentPath = r.Snapshot().File
			initDownloaded = false
		}

		playlist, err := r.getBody(ctx, authURL)
		if err != nil {
			r.setError(err)
			if !waitContext(ctx, r.stopChan, r.retryDelay) {
				return r.finishSegment(file, currentPath, "最终")
			}
			continue
		}
		playlistText := string(playlist)
		if hls.IsAdPlaylist(playlistText) {
			if !waitContext(ctx, r.stopChan, r.retryDelay) {
				return r.finishSegment(file, currentPath, "最终")
			}
			continue
		}

		baseURL := hls.GetBaseURL(variantURL)
		if !initDownloaded {
			if initURL := hls.GetInitSegmentURL(playlistText, baseURL); initURL != "" {
				data, downloadErr := r.getBody(ctx, initURL)
				if downloadErr == nil {
					if err := writeAndSync(file, data); err != nil {
						return err
					}
					r.addBytes(int64(len(data)))
					initDownloaded = true
				}
			}
		}

		segments, _ := hls.BuildMouflonSegmentURLs(playlistText, baseURL, psch, pkey, decryptKey)
		downloaded := false
		for _, segment := range segments {
			if seen[segment.URL] {
				continue
			}
			segmentURL := mouflon.AppendAuthParams(segment.URL, psch, pkey, decryptKey)
			data, downloadErr := r.getBody(ctx, segmentURL)
			if downloadErr != nil {
				continue
			}
			if err := writeAndSync(file, data); err != nil {
				return err
			}
			seen[segment.URL] = true
			r.addBytes(int64(len(data)))
			downloaded = true
		}
		if downloaded {
			mediaReceived = true
			lastData = time.Now()
		}
		if !waitContext(ctx, r.stopChan, r.pollInterval) {
			return r.finishSegment(file, currentPath, "最终")
		}
	}
}

func (r *Recorder) openSegment() (segmentWriter, error) {
	now := time.Now()
	snapshot := config.Get().Snapshot()
	path := filepath.Join(snapshot.SaveDirectory, r.model, fmt.Sprintf("%s_%s.mp4", now.Format("2006.01.02_15.04.05.000"), r.model))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	var writer segmentWriter = syncedFile{file}
	// The name is reserved above; FFmpeg then writes the fragmented MP4 into it. Without
	// FFmpeg the raw segments are kept and remuxed after recording, as before.
	if ffmpeg, lookErr := exec.LookPath("ffmpeg"); lookErr == nil {
		_ = file.Close()
		sink, sinkErr := newFMP4Sink(ffmpeg, path)
		if sinkErr != nil {
			_ = os.Remove(path)
			return nil, sinkErr
		}
		writer = sink
	}
	r.mu.Lock()
	if r.recordStartTime.IsZero() {
		r.recordStartTime = now
	}
	r.file = path
	r.segmentStart = now
	r.bytes = 0
	r.online = true
	r.status = "recording"
	r.lastError = ""
	r.mu.Unlock()
	return writer, nil
}

func (r *Recorder) finishSegment(file segmentWriter, path, label string) error {
	if file != nil {
		if err := file.Close(); err != nil {
			// FFmpeg failing to finish still leaves the fragments it wrote playable.
			logger.Event("[%s] 关闭录制文件出错: %s - %v", r.model, filepath.Base(path), err)
		}
	}
	r.mu.Lock()
	r.online = false
	if r.status == "recording" {
		r.status = "offline"
	}
	r.mu.Unlock()
	return r.handleCompletedFile(path, label)
}

func (r *Recorder) handleCompletedFile(path, label string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Size() <= minFileSize {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		logger.Event("删除过小%s文件: %s", label, path)
		return nil
	}
	if isLiveFragmentedMP4(path) {
		// Written as fragmented MP4 while recording: already playable, nothing to remux.
	} else if err := fixTimestamps(path); err != nil {
		logger.Event("[ffmpeg] 时间戳修复失败，保留原文件: %s - %v", filepath.Base(path), err)
	}
	return r.moveFileToUp(path)
}

// ProcessCompletedFile repairs and queues a recording left in captures after a restart.
func ProcessCompletedFile(path, model string) error {
	r := &Recorder{model: model}
	return r.handleCompletedFile(path, "遗留")
}

func fixTimestamps(path string) error {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	ext := filepath.Ext(path)
	fixed := filepath.Join(dir, strings.TrimSuffix(filepath.Base(path), ext)+"_fixed"+ext)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpeg, "-y", "-fflags", "+genpts", "-i", path, "-c", "copy", "-avoid_negative_ts", "make_zero", "-movflags", "+faststart", fixed)
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(fixed)
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	if info, err := os.Stat(fixed); err != nil || info.Size() == 0 {
		_ = os.Remove(fixed)
		return errors.New("ffmpeg produced no output")
	}
	if err := os.Rename(fixed, path); err != nil {
		_ = os.Remove(fixed)
		return err
	}
	return nil
}

func (r *Recorder) moveFileToUp(path string) error {
	snapshot := config.Get().Snapshot()
	destinationDir := filepath.Join(snapshot.UpDirectory, r.model)
	if err := os.MkdirAll(destinationDir, 0o755); err != nil {
		return err
	}
	destination := filepath.Join(destinationDir, filepath.Base(path))
	if _, err := os.Stat(destination); err == nil {
		ext := filepath.Ext(destination)
		destination = strings.TrimSuffix(destination, ext) + "_" + time.Now().Format("150405.000") + ext
	}
	if err := os.Rename(path, destination); err != nil {
		return fmt.Errorf("move completed file: %w", err)
	}
	logger.Event("文件已移动到上传队列: %s", destination)
	return nil
}

func httpCheckError(code int) *CheckError {
	kind := "http_error"
	switch code {
	case http.StatusNotFound:
		kind = "not_found"
	case http.StatusForbidden:
		kind = "cloudflare_forbidden"
	case http.StatusTeapot:
		// Stripchat answers 418 on endpoints it refuses to serve to anyone.
		kind = "blocked"
	case http.StatusTooManyRequests:
		kind = "rate_limited"
	default:
		if code >= 500 {
			kind = "server_error"
		}
	}
	return &CheckError{Kind: kind, StatusCode: code}
}

// resolveModelID maps the wishlist name to Stripchat's numeric model id. Lookups by
// username (/api/front/v2/models/username/<name>/cam) now answer 418 to every client,
// browsers included, while the id-based endpoint still serves the same payload. The
// id is cached; it is dropped whenever the cam endpoint stops confirming it.
func (r *Recorder) resolveModelID(ctx context.Context) (int64, *CheckError) {
	r.mu.RLock()
	id := r.modelID
	r.mu.RUnlock()
	if id != 0 {
		return id, nil
	}
	// About one page in four is served as a bare shell without the rendered model
	// state; that says nothing about the model, so it is retried, and if every
	// attempt is a shell the check fails as transient rather than not_found.
	var checkErr *CheckError
	for attempt := 0; attempt < modelPageAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, &CheckError{Kind: "network", Err: ctx.Err()}
			case <-time.After(modelPageRetryDelay):
			}
		}
		id, checkErr = r.fetchModelID(ctx)
		if checkErr == nil || checkErr.Kind != "page_unavailable" {
			break
		}
	}
	if checkErr != nil {
		return 0, checkErr
	}
	r.mu.Lock()
	r.modelID = id
	r.mu.Unlock()
	return id, nil
}

func (r *Recorder) fetchModelID(ctx context.Context) (int64, *CheckError) {
	response, err := r.doRequest(ctx, r.apiBaseURL+"/"+url.PathEscape(r.model))
	if err != nil {
		return 0, &CheckError{Kind: "network", Err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, httpCheckError(response.StatusCode)
	}
	// A name that no longer belongs to a model is redirected to its user profile.
	if !strings.EqualFold(strings.Trim(response.Request.URL.Path, "/"), r.model) {
		return 0, &CheckError{Kind: "not_found", Err: errors.New("not a model page")}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, requestBodyLimit))
	if err != nil {
		return 0, &CheckError{Kind: "network", Err: err}
	}
	if id := modelIDFromPage(body, r.model); id != 0 {
		return id, nil
	}
	if kind := pageErrorType(body); kind != "" {
		// The page states why no model is shown, e.g. "deletedPopular".
		return 0, &CheckError{Kind: "not_found", Err: errors.New("model page reports " + kind)}
	}
	return 0, &CheckError{Kind: "page_unavailable", Err: errors.New("model page served without model state")}
}

func (r *Recorder) forgetModelID() {
	r.mu.Lock()
	r.modelID = 0
	r.mu.Unlock()
}

// pageErrorType is the reason the page gives for not showing a model, if any.
func pageErrorType(page []byte) string {
	match := preloadedStatePattern.FindSubmatch(page)
	if match == nil {
		return ""
	}
	var state struct {
		ViewCamBase struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		} `json:"viewCamBase"`
	}
	if json.Unmarshal(match[1], &state) != nil {
		return ""
	}
	return state.ViewCamBase.Error.Type
}

func modelIDFromPage(page []byte, model string) int64 {
	match := preloadedStatePattern.FindSubmatch(page)
	if match == nil {
		return 0
	}
	decoder := json.NewDecoder(strings.NewReader(string(match[1])))
	decoder.UseNumber()
	var state any
	if decoder.Decode(&state) != nil {
		return 0
	}
	var find func(any) int64
	find = func(node any) int64 {
		switch value := node.(type) {
		case map[string]any:
			if name, ok := value["username"].(string); ok && strings.EqualFold(name, model) {
				if number, ok := value["id"].(json.Number); ok {
					if id, err := number.Int64(); err == nil && id > 0 {
						return id
					}
				}
			}
			for _, child := range value {
				if id := find(child); id != 0 {
					return id
				}
			}
		case []any:
			for _, child := range value {
				if id := find(child); id != 0 {
					return id
				}
			}
		}
		return 0
	}
	return find(state)
}

func (r *Recorder) CheckOnline(ctx context.Context) (OnlineInfo, error) {
	id, checkErr := r.resolveModelID(ctx)
	if checkErr != nil {
		r.publishCheck(OnlineInfo{}, checkErr)
		return OnlineInfo{}, checkErr
	}
	endpoint := fmt.Sprintf("%s/api/front/v2/models/%d/cam", r.apiBaseURL, id)
	response, err := r.doRequest(ctx, endpoint)
	if err != nil {
		checkErr := &CheckError{Kind: "network", Err: err}
		r.publishCheck(OnlineInfo{}, checkErr)
		return OnlineInfo{}, checkErr
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusNotFound {
			r.forgetModelID()
		}
		checkErr := httpCheckError(response.StatusCode)
		r.publishCheck(OnlineInfo{}, checkErr)
		return OnlineInfo{}, checkErr
	}

	var payload struct {
		Cam  json.RawMessage `json:"cam"`
		User struct {
			User struct {
				Status   string `json:"status"`
				Username string `json:"username"`
			} `json:"user"`
		} `json:"user"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, requestBodyLimit))
	if err := decoder.Decode(&payload); err != nil {
		checkErr := &CheckError{Kind: "invalid_response", Err: err}
		r.publishCheck(OnlineInfo{}, checkErr)
		return OnlineInfo{}, checkErr
	}
	// Guard against a wrongly resolved id: the payload must describe this model.
	if name := payload.User.User.Username; name != "" && !strings.EqualFold(name, r.model) {
		r.forgetModelID()
		checkErr := &CheckError{Kind: "invalid_response", Err: fmt.Errorf("model id resolves to %q", name)}
		r.publishCheck(OnlineInfo{}, checkErr)
		return OnlineInfo{}, checkErr
	}
	var cam struct {
		IsCamAvailable bool   `json:"isCamAvailable"`
		StreamName     string `json:"streamName"`
	}
	camValue := strings.TrimSpace(string(payload.Cam))
	if camValue != "" && camValue != "null" && camValue != "[]" {
		if err := json.Unmarshal(payload.Cam, &cam); err != nil {
			checkErr := &CheckError{Kind: "invalid_response", Err: fmt.Errorf("decode cam: %w", err)}
			r.publishCheck(OnlineInfo{}, checkErr)
			return OnlineInfo{}, checkErr
		}
	}
	info := OnlineInfo{Available: cam.IsCamAvailable, StreamName: cam.StreamName, Status: payload.User.User.Status}
	if info.Status == "" {
		info.Status = "offline"
	}
	r.publishCheck(info, nil)
	return info, nil
}

func (r *Recorder) publishCheck(info OnlineInfo, checkErr *CheckError) {
	status := info.Status
	errorText := ""
	httpStatus := 0
	if checkErr != nil {
		status = checkErr.Kind
		errorText = checkErr.Error()
		httpStatus = checkErr.StatusCode
	}
	r.mu.Lock()
	r.online = info.Available && info.Status == "public"
	r.status = status
	r.streamName = info.StreamName
	callback := r.onStatusChange
	r.mu.Unlock()
	if callback != nil {
		callback(ModelStatus{Model: r.model, Status: status, Error: errorText, HTTPStatus: httpStatus, CheckedAt: time.Now().UTC()})
	}
}

func (r *Recorder) doRequest(ctx context.Context, endpoint string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range DefaultHeaders {
		request.Header.Set(key, value)
	}
	return r.httpClient.Do(request)
}

func (r *Recorder) getBody(ctx context.Context, endpoint string) ([]byte, error) {
	response, err := r.doRequest(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, requestBodyLimit))
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (r *Recorder) setError(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	r.lastError = err.Error()
	r.mu.Unlock()
}

func (r *Recorder) addBytes(size int64) {
	r.mu.Lock()
	r.bytes += size
	r.mu.Unlock()
}

func (r *Recorder) isStopped() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stopped
}

func waitContext(ctx context.Context, stop <-chan struct{}, duration time.Duration) bool {
	if duration <= 0 {
		select {
		case <-ctx.Done():
			return false
		case <-stop:
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-stop:
		return false
	case <-timer.C:
		return true
	}
}

func writeAndSync(file segmentWriter, data []byte) error {
	if len(data) == 0 {
		return errors.New("empty segment")
	}
	_, err := file.Write(data)
	return err
}

// syncedFile writes raw segments straight to disk (when FFmpeg is unavailable),
// syncing after each so a crash loses at most the segment being written.
type syncedFile struct{ *os.File }

func (f syncedFile) Write(p []byte) (int, error) {
	n, err := f.File.Write(p)
	if err != nil {
		return n, err
	}
	return n, f.File.Sync()
}

func (f syncedFile) Close() error {
	if err := f.File.Sync(); err != nil {
		_ = f.File.Close()
		return err
	}
	return f.File.Close()
}
