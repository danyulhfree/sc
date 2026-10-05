package recorder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Stripchat sends fragmented-MP4 HLS segments, each with its own sidx. Written back to
// back they make a file that browsers read from end to end before playing it, so it
// used to be remuxed in full after recording. Instead the segments now go through one
// `ffmpeg -c copy` per output file that writes a fragmented MP4 as data arrives: a moof
// per keyframe and no sidx (playable at any moment, even if the recorder is killed),
// timestamps starting at 0, and on a clean close a final mfra index. Nothing is re-encoded
// and nothing has to be rewritten afterwards.

var fmp4CloseTimeout = 15 * time.Second

// segmentWriter receives one output file's init segment and media segments.
type segmentWriter interface {
	io.Writer
	Close() error
}

type fmp4Sink struct {
	path   string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stderr *tailBuffer
	done   chan struct{}
	err    error // exit status, valid once done is closed

	closeOnce sync.Once
	closeErr  error
}

func fmp4Args(path string) []string {
	return []string{
		"-hide_banner", "-nostdin", "-loglevel", "error", "-y",
		"-fflags", "+genpts", "-f", "mp4", "-i", "pipe:0",
		"-map", "0", "-c", "copy", "-avoid_negative_ts", "make_zero",
		"-movflags", "+frag_keyframe+empty_moov+default_base_moof",
		// hand every packet to the OS at once, so a killed recorder loses nothing it had
		"-flush_packets", "1",
		"-f", "mp4", path,
	}
}

func newFMP4Sink(ffmpeg, path string) (*fmp4Sink, error) {
	cmd := exec.Command(ffmpeg, fmp4Args(path)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	sink := &fmp4Sink{path: path, cmd: cmd, stdin: stdin, stderr: &tailBuffer{limit: 2048}, done: make(chan struct{})}
	cmd.Stderr = sink.stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		sink.err = cmd.Wait()
		close(sink.done)
	}()
	return sink, nil
}

func (s *fmp4Sink) exited() error {
	select {
	case <-s.done:
		detail := strings.TrimSpace(s.stderr.String())
		if detail != "" {
			return fmt.Errorf("ffmpeg 封装进程已退出（%v）: %s", s.err, detail)
		}
		return fmt.Errorf("ffmpeg 封装进程已退出（%v）", s.err)
	default:
		return nil
	}
}

func (s *fmp4Sink) Write(p []byte) (int, error) {
	if err := s.exited(); err != nil {
		return 0, err
	}
	n, err := s.stdin.Write(p)
	if err != nil {
		if exitErr := s.exited(); exitErr != nil {
			return n, exitErr
		}
		return n, fmt.Errorf("写入 ffmpeg 封装进程失败: %w", err)
	}
	return n, nil
}

// Close lets FFmpeg write its last fragment and the index, killing it after
// fmp4CloseTimeout. Safe to call more than once.
func (s *fmp4Sink) Close() error {
	s.closeOnce.Do(func() {
		_ = s.stdin.Close()
		timer := time.NewTimer(fmp4CloseTimeout)
		defer timer.Stop()
		select {
		case <-s.done:
			if s.err != nil {
				s.closeErr = s.exited()
			}
		case <-timer.C:
			_ = s.cmd.Process.Kill()
			<-s.done
			s.closeErr = errors.New("ffmpeg 封装进程收尾超时，已强制结束")
		}
	})
	return s.closeErr
}

// tailBuffer keeps the last `limit` bytes written to it (FFmpeg's error output).
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.limit {
		b.buf = b.buf[len(b.buf)-b.limit:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// isLiveFragmentedMP4 reports whether path was written by fmp4Sink: an MP4 whose moov
// announces fragments (mvex) and whose first fragment follows directly, with no sidx.
// Such a file needs no remux. Raw segment dumps (sidx before every moof) still do.
func isLiveFragmentedMP4(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	head := make([]byte, 256<<10)
	n, _ := io.ReadFull(file, head)
	head = head[:n]
	moovEnd, fragmented := -1, false
	for i := 0; i+8 <= len(head); {
		size := int(binary.BigEndian.Uint32(head[i:]))
		kind := string(head[i+4 : i+8])
		if size < 8 {
			return false
		}
		if moovEnd >= 0 {
			return fragmented && kind == "moof"
		}
		if kind == "moov" {
			end := i + size
			if end > len(head) {
				return false
			}
			fragmented = bytes.Contains(head[i+8:end], []byte("mvex"))
			moovEnd = end
		} else if kind == "moof" || kind == "mdat" || kind == "sidx" {
			return false
		}
		i += size
	}
	return false
}
