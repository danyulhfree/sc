package hls

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/mio/sc/internal/mouflon"
)

var (
	streamInfRe   = regexp.MustCompile(`#EXT-X-STREAM-INF:(.+)`)
	bandwidthRe   = regexp.MustCompile(`BANDWIDTH=(\d+)`)
	resolutionRe  = regexp.MustCompile(`RESOLUTION=(\d+)x(\d+)`)
	initSegmentRe = regexp.MustCompile(`#EXT-X-MAP:URI="([^"]+)"`)
	partURIRe     = regexp.MustCompile(`URI="([^"]+)"`)
)

// Variant 表示一个 HLS 变体流
type Variant struct {
	URL       string
	Bandwidth int
	Width     int
	Height    int
}

// ParseMaster 解析 master m3u8 并返回变体列表
func ParseMaster(content, baseURL string) []Variant {
	var variants []Variant
	lines := strings.Split(content, "\n")

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "#EXT-X-STREAM-INF:") {
			continue
		}

		attrs := streamInfRe.FindStringSubmatch(line)
		if len(attrs) < 2 {
			continue
		}

		v := Variant{}

		// 解析带宽
		if m := bandwidthRe.FindStringSubmatch(attrs[1]); len(m) >= 2 {
			v.Bandwidth, _ = strconv.Atoi(m[1])
		}

		// 解析分辨率
		if m := resolutionRe.FindStringSubmatch(attrs[1]); len(m) >= 3 {
			v.Width, _ = strconv.Atoi(m[1])
			v.Height, _ = strconv.Atoi(m[2])
		}

		// 查找 URL (下一个非注释行)
		for j := i + 1; j < len(lines); j++ {
			nextLine := strings.TrimSpace(lines[j])
			if nextLine == "" || strings.HasPrefix(nextLine, "#") {
				continue
			}
			v.URL = NormalizeURL(nextLine, baseURL)
			i = j
			break
		}

		if v.URL != "" {
			variants = append(variants, v)
		}
	}

	return variants
}

// PickBestVariant 选择最高质量的变体
func PickBestVariant(variants []Variant) *Variant {
	if len(variants) == 0 {
		return nil
	}

	best := &variants[0]
	for i := 1; i < len(variants); i++ {
		v := &variants[i]
		// 优先比较分辨率高度，其次带宽
		if v.Height > best.Height ||
			(v.Height == best.Height && v.Width > best.Width) ||
			(v.Height == best.Height && v.Width == best.Width && v.Bandwidth > best.Bandwidth) {
			best = v
		}
	}
	return best
}

// GetInitSegmentURL 从变体 m3u8 中提取 init segment URL
func GetInitSegmentURL(content, baseURL string) string {
	match := initSegmentRe.FindStringSubmatch(content)
	if len(match) >= 2 {
		return NormalizeURL(match[1], baseURL)
	}
	return ""
}

// PKeyPair 表示 psch/pkey 对
type PKeyPair struct {
	Psch string
	Pkey string
}

// GetMouflonPKeys 从 m3u8 中提取 MOUFLON pkey 对
func GetMouflonPKeys(content string) []PKeyPair {
	var pairs []PKeyPair
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#EXT-X-MOUFLON:PSCH:") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 4 {
			pairs = append(pairs, PKeyPair{
				Psch: parts[2],
				Pkey: strings.TrimSpace(parts[3]),
			})
		}
	}
	return pairs
}

// GetMouflonFileEntries 提取 MOUFLON:FILE 加密条目
func GetMouflonFileEntries(content string) []string {
	var entries []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#EXT-X-MOUFLON:FILE:") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) >= 3 {
			entries = append(entries, strings.TrimSpace(parts[2]))
		}
	}
	return entries
}

// SegmentInfo 表示一个分段信息
type SegmentInfo struct {
	URL      string
	Duration float64
}

// BuildMouflonSegmentURLs 构建真实的分段 URL
func BuildMouflonSegmentURLs(content, baseURL, psch, pkey, pdkey string) ([]SegmentInfo, int) {
	var segments []SegmentInfo
	var pendingURI string
	expectURIAfterINF := false
	replaced := 0

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		// 处理 MOUFLON:URI
		if strings.HasPrefix(line, "#EXT-X-MOUFLON:URI:") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 3 {
				pendingURI = strings.TrimSpace(parts[2])
				// V2 解密
				if psch == "v2" && pdkey != "" {
					if decoded := mouflon.DecodeURI(pendingURI, pdkey); decoded != "" {
						pendingURI = decoded
					}
				}
			}
			continue
		}

		// 处理 #EXT-X-PART
		if strings.HasPrefix(line, "#EXT-X-PART:") {
			match := partURIRe.FindStringSubmatch(line)
			if len(match) < 2 {
				continue
			}
			partURI := match[1]
			realURI := partURI
			if pendingURI != "" {
				realURI = pendingURI
				replaced++
				pendingURI = ""
			}
			segURL := NormalizeURL(realURI, baseURL)
			segments = append(segments, SegmentInfo{URL: segURL})
			continue
		}

		// 处理 #EXTINF
		if strings.HasPrefix(line, "#EXTINF:") {
			expectURIAfterINF = true
			continue
		}

		// 跳过其他注释
		if strings.HasPrefix(line, "#") {
			continue
		}

		// 分段 URI
		if expectURIAfterINF {
			realURI := line
			if pendingURI != "" {
				realURI = pendingURI
				replaced++
				pendingURI = ""
			}
			expectURIAfterINF = false
			segURL := NormalizeURL(realURI, baseURL)
			segments = append(segments, SegmentInfo{URL: segURL})
		}
	}

	return segments, replaced
}

// IsAdPlaylist 检测是否是广告播放列表
func IsAdPlaylist(content string) bool {
	return strings.Contains(content, "MOUFLON-ADVERT") || strings.Contains(content, "/cpa/")
}

// NormalizeURL 将相对 URL 转为绝对 URL
func NormalizeURL(uri, baseURL string) string {
	if uri == "" {
		return uri
	}
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return uri
	}
	ref, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	return base.ResolveReference(ref).String()
}

// ExtractStreamName 从 HLS URL 中提取 stream name
func ExtractStreamName(hlsURL string) string {
	re := regexp.MustCompile(`/hls/([^/]+)/`)
	match := re.FindStringSubmatch(hlsURL)
	if len(match) >= 2 {
		return match[1]
	}
	return ""
}

// GetBaseURL 获取 URL 的基础路径
func GetBaseURL(fullURL string) string {
	idx := strings.LastIndex(fullURL, "/")
	if idx > 0 {
		return fullURL[:idx]
	}
	return fullURL
}
