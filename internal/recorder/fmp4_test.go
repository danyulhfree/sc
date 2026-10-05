package recorder

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func needFFmpeg(t *testing.T) (string, string) {
	t.Helper()
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not installed")
	}
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not installed")
	}
	return ffmpeg, ffprobe
}

// stripchatDump builds what the recorder used to write: an init segment followed by
// fragments that each carry a sidx, like Stripchat's CMAF HLS segments.
func stripchatDump(t *testing.T, ffmpeg string, seconds int) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "dump.mp4")
	cmd := exec.Command(ffmpeg, "-v", "error", "-y",
		"-f", "lavfi", "-i", "testsrc2=size=320x180:rate=25",
		"-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000",
		"-t", strconv.Itoa(seconds), "-c:v", "libx264", "-preset", "ultrafast", "-g", "50", "-pix_fmt", "yuv420p",
		"-c:a", "aac", "-movflags", "+frag_keyframe+empty_moov+default_base_moof+dash", "-f", "mp4", out)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ffmpeg: %v %s", err, output)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func topLevelBoxes(data []byte) []string {
	var boxes []string
	for i := 0; i+8 <= len(data); {
		size := int(binary.BigEndian.Uint32(data[i:]))
		if size < 8 {
			break
		}
		boxes = append(boxes, string(data[i+4:i+8]))
		i += size
	}
	return boxes
}

func probeDuration(t *testing.T, ffprobe, path string) (float64, string) {
	t.Helper()
	output, err := exec.Command(ffprobe, "-v", "error", "-show_entries", "format=duration:stream=codec_name",
		"-of", "json", path).Output()
	if err != nil {
		t.Fatalf("ffprobe %s: %v", path, err)
	}
	var probe struct {
		Format struct {
			Duration string `json:"duration"`
		} `json:"format"`
		Streams []struct {
			CodecName string `json:"codec_name"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(output, &probe); err != nil {
		t.Fatal(err)
	}
	var codecs []string
	for _, s := range probe.Streams {
		codecs = append(codecs, s.CodecName)
	}
	duration, _ := strconv.ParseFloat(probe.Format.Duration, 64)
	return duration, strings.Join(codecs, ",")
}

func writeInChunks(t *testing.T, sink segmentWriter, data []byte) {
	t.Helper()
	for i := 0; i < len(data); i += 64 << 10 {
		end := min(i+64<<10, len(data))
		if err := writeAndSync(sink, data[i:end]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFMP4SinkRemuxesSegmentsWhileRecording(t *testing.T) {
	ffmpeg, ffprobe := needFFmpeg(t)
	dump := stripchatDump(t, ffmpeg, 8)
	if !strings.Contains(strings.Join(topLevelBoxes(dump), ","), "sidx") {
		t.Fatal("fixture should carry a sidx per fragment")
	}
	out := filepath.Join(t.TempDir(), "rec.mp4")
	sink, err := newFMP4Sink(ffmpeg, out)
	if err != nil {
		t.Fatal(err)
	}
	writeInChunks(t, sink, dump)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	boxes := topLevelBoxes(data)
	joined := strings.Join(boxes, ",")
	if !strings.HasPrefix(joined, "ftyp,moov,moof,mdat") || boxes[len(boxes)-1] != "mfra" || strings.Contains(joined, "sidx") {
		t.Fatalf("boxes: %v", boxes)
	}
	if !isLiveFragmentedMP4(out) {
		t.Fatal("sink output not recognised")
	}
	duration, codecs := probeDuration(t, ffprobe, out)
	if duration < 7.5 || duration > 8.5 || codecs != "h264,aac" {
		t.Fatalf("duration %.2f codecs %s", duration, codecs)
	}
}

func TestFMP4SinkKilledMidFileStaysPlayable(t *testing.T) {
	ffmpeg, ffprobe := needFFmpeg(t)
	dump := stripchatDump(t, ffmpeg, 20)
	out := filepath.Join(t.TempDir(), "rec.mp4")
	sink, err := newFMP4Sink(ffmpeg, out)
	if err != nil {
		t.Fatal(err)
	}
	writeInChunks(t, sink, dump)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(out)
		if strings.Count(strings.Join(topLevelBoxes(data), ","), "moof") >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = sink.cmd.Process.Kill()
	<-sink.done
	var writeErr error
	for i := 0; i < 64 && writeErr == nil; i++ {
		_, writeErr = sink.Write(make([]byte, 64<<10))
	}
	if writeErr == nil || !strings.Contains(writeErr.Error(), "ffmpeg") {
		t.Fatalf("write after the muxer died: %v", writeErr)
	}
	_ = sink.Close()
	if !isLiveFragmentedMP4(out) {
		t.Fatal("killed output not recognised")
	}
	if duration, codecs := probeDuration(t, ffprobe, out); duration <= 0 || !strings.HasPrefix(codecs, "h264") {
		t.Fatalf("killed output: %.2f %s", duration, codecs)
	}
}

func TestFMP4SinkCloseKillsAStuckMuxer(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "ffmpeg")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := fmp4CloseTimeout
	fmp4CloseTimeout = 200 * time.Millisecond
	defer func() { fmp4CloseTimeout = old }()
	sink, err := newFMP4Sink(fake, filepath.Join(dir, "x.mp4"))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := sink.Close(); err == nil || time.Since(started) > 5*time.Second {
		t.Fatalf("close: %v after %v", err, time.Since(started))
	}
}

func TestIsLiveFragmentedMP4(t *testing.T) {
	ffmpeg, _ := needFFmpeg(t)
	dir := t.TempDir()
	dump := filepath.Join(dir, "dump.mp4")
	if err := os.WriteFile(dump, stripchatDump(t, ffmpeg, 3), 0o640); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain.mp4")
	if output, err := exec.Command(ffmpeg, "-v", "error", "-y", "-i", dump, "-c", "copy", "-movflags", "+faststart", plain).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, output)
	}
	for path, want := range map[string]bool{dump: false, plain: false, filepath.Join(dir, "missing.mp4"): false} {
		if got := isLiveFragmentedMP4(path); got != want {
			t.Errorf("%s: %v, want %v", filepath.Base(path), got, want)
		}
	}
}

// A file written through the sink goes to the upload queue as it is; a raw segment
// dump left over from before (or from a run without FFmpeg) is still remuxed.
func TestCompletedFilesSkipRemuxOnlyWhenAlreadyFragmented(t *testing.T) {
	ffmpeg, _ := needFFmpeg(t)
	captures, upDir := initRecorderConfig(t)
	r := &Recorder{model: "model"}
	if err := os.MkdirAll(filepath.Join(captures, "model"), 0o755); err != nil {
		t.Fatal(err)
	}
	dump := stripchatDump(t, ffmpeg, 4)

	live := filepath.Join(captures, "model", "live.mp4")
	sink, err := newFMP4Sink(ffmpeg, live)
	if err != nil {
		t.Fatal(err)
	}
	writeInChunks(t, sink, dump)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	written, _ := os.ReadFile(live)
	raw := filepath.Join(captures, "model", "raw.mp4")
	if err := os.WriteFile(raw, dump, 0o640); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{live, raw} {
		if err := r.handleCompletedFile(path, "test"); err != nil {
			t.Fatal(err)
		}
	}
	queued, _ := os.ReadFile(filepath.Join(upDir, "model", "live.mp4"))
	if !bytes.Equal(queued, written) {
		t.Fatal("fragmented recording was rewritten")
	}
	remuxed, _ := os.ReadFile(filepath.Join(upDir, "model", "raw.mp4"))
	if boxes := strings.Join(topLevelBoxes(remuxed), ","); strings.Contains(boxes, "sidx") || strings.Contains(boxes, "moof") {
		t.Fatalf("raw dump not remuxed: %s", boxes)
	}
}
