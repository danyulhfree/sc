package mouflon

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var (
	// 内置密钥
	keys = map[string][]string{
		"Zeechoej4aleeshi": {"ubahjae7goPoodi6"},
	}
	keysMu   sync.RWMutex
	keysMod  int64 // 文件修改时间
	keysPath string

	// URI 正则
	uriEncodedRe = regexp.MustCompile(`_(\d+)_([^_]+)_(\d+)(?:_part\d+)?\.(?:mp4|m4s)$`)
)

// Init 初始化模块
func Init(mainDir string) {
	keysPath = filepath.Join(mainDir, "stripchat_mouflon_keys.json")
	LoadKeys()
}

// LoadKeys 从 JSON 文件加载密钥
func LoadKeys() {
	info, err := os.Stat(keysPath)
	if err != nil {
		return
	}
	if keysMod != 0 && info.ModTime().Unix() <= keysMod {
		return
	}
	keysMod = info.ModTime().Unix()

	data, err := os.ReadFile(keysPath)
	if err != nil {
		return
	}

	var loaded map[string]interface{}
	if json.Unmarshal(data, &loaded) != nil {
		return
	}

	keysMu.Lock()
	defer keysMu.Unlock()

	for pkey, val := range loaded {
		var candidates []string
		switch v := val.(type) {
		case string:
			if v != "" {
				candidates = []string{v}
			}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok && s != "" {
					candidates = append(candidates, s)
				}
			}
		}
		if len(candidates) > 0 {
			// 合并已有密钥
			existing := keys[pkey]
			merged := existing
			for _, c := range candidates {
				found := false
				for _, e := range existing {
					if e == c {
						found = true
						break
					}
				}
				if !found {
					merged = append(merged, c)
				}
			}
			keys[pkey] = merged
		}
	}
}

// GetDecryptKey 获取解密密钥列表
func GetDecryptKey(pkey string) []string {
	keysMu.RLock()
	defer keysMu.RUnlock()
	return keys[pkey]
}

// HasKey 检查是否有对应的密钥
func HasKey(pkey string) bool {
	keysMu.RLock()
	defer keysMu.RUnlock()
	_, ok := keys[pkey]
	return ok
}

// isRawKey 检查是否是原始密钥格式 (sha256: 或 mask:)
func isRawKey(key string) bool {
	return strings.HasPrefix(key, "sha256:") || strings.HasPrefix(key, "mask:")
}

// parseKeyBytes 解析密钥为字节
func parseKeyBytes(key string) []byte {
	if key == "" {
		return nil
	}
	if isRawKey(key) {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) < 2 {
			return nil
		}
		hexVal := strings.TrimSpace(parts[1])
		b, err := hex.DecodeString(hexVal)
		if err != nil {
			return nil
		}
		return b
	}
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

// Decode 解密 v1 加密字符串
func Decode(encrypted, key string) string {
	hashBytes := parseKeyBytes(key)
	if hashBytes == nil {
		return ""
	}
	hashLen := len(hashBytes)

	// 尝试不同的 padding 和 base64 变体
	variants := []string{encrypted, encrypted + "=", encrypted + "=="}
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}

	for _, padded := range variants {
		for _, decoder := range decoders {
			data, err := decoder(padded)
			if err != nil {
				continue
			}
			result := make([]byte, len(data))
			for i, b := range data {
				result[i] = b ^ hashBytes[i%hashLen]
			}
			return string(result)
		}
	}
	return ""
}

// DecodeV2 解密 v2 加密字符串 (reverse + v1)
func DecodeV2(encrypted, key string) string {
	if encrypted == "" || key == "" {
		return ""
	}
	// 按字节反转 (与 Python 的 [::-1] 一致)
	bytes := []byte(encrypted)
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return Decode(string(bytes), key)
}

// DecodeURI 解密 #EXT-X-MOUFLON:URI 中的加密部分
func DecodeURI(uri, key string) string {
	if uri == "" || key == "" {
		return ""
	}
	match := uriEncodedRe.FindStringSubmatch(uri)
	if len(match) < 3 {
		return ""
	}
	encryptedPart := match[2]
	decodedPart := DecodeV2(encryptedPart, key)
	if decodedPart == "" {
		return ""
	}
	// 验证解密结果：如果包含控制字符（非法URL字符），认为解密失败
	if !isValidURLPart(decodedPart) {
		return ""
	}
	return strings.Replace(uri, encryptedPart, decodedPart, 1)
}

// isValidURLPart 检查字符串是否是有效的URL片段（不含控制字符）
func isValidURLPart(s string) bool {
	for _, r := range s {
		// 控制字符 (0x00-0x1F) 或 DEL (0x7F) 或非ASCII高位字符在URL中无效
		if r < 0x20 || r == 0x7F || r > 0x7E {
			return false
		}
	}
	return true
}

// AppendAuthParams 为 URL 添加认证参数
func AppendAuthParams(url, psch, pkey, pdkey string) string {
	if url == "" || psch == "" || pkey == "" {
		return url
	}
	if isRawKey(pdkey) {
		pdkey = ""
	}
	if strings.Contains(url, "psch=") && strings.Contains(url, "pkey=") {
		return url
	}

	sep := "&"
	if !strings.Contains(url, "?") {
		sep = "?"
	}
	url = url + sep + "psch=" + psch + "&pkey=" + pkey
	if pdkey != "" && !strings.Contains(url, "pdkey=") {
		url = url + "&pdkey=" + pdkey
	}
	return url
}
