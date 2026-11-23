package crypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// AuthKeyMinLength 是 web api 签名密钥的最小长度
	AuthKeyMinLength = 16
	// AuthTimestampSkew 是允许的时间戳偏差（秒）
	AuthTimestampSkew = 20
	// AuthCryptKeyLength 是 auth_crypt_key 固定长度
	AuthCryptKeyLength = 16
	// AuthNonceMinLength 是 nonce 的最小长度
	AuthNonceMinLength = 8
	// AuthNonceMaxLength 是 nonce 的最大长度
	AuthNonceMaxLength = 64
)

var (
	ErrAuthKeyNotConfigured = errors.New("auth_key is not configured")
	ErrAuthKeyTooShort      = errors.New("auth_key is shorter than 16 bytes")
	ErrAuthKeyWeak          = errors.New("auth_key is a well-known weak value")
	ErrAuthTimestamp        = errors.New("timestamp out of allowed window")
	ErrAuthSignature        = errors.New("invalid auth signature")
	ErrAuthNonce            = errors.New("invalid auth nonce")
	ErrAuthNonceReplayed    = errors.New("auth nonce already used")

	ErrAuthCryptKeyNotConfigured = errors.New("auth_crypt_key is not configured")
	ErrAuthCryptKeyLength        = errors.New("auth_crypt_key length is not 16")
	ErrAuthCryptKeyWeak          = errors.New("auth_crypt_key is a well-known weak value")
)

// knownWeakAuthKeys 是官方示例值和常见弱口令。这些值和未配置等价，
// 都允许攻击者离线算出合法签名，必须拒绝。
var knownWeakAuthKeys = map[string]struct{}{
	"test":             {},
	"123":              {},
	"1234":             {},
	"12345":            {},
	"123456":           {},
	"12345678":         {},
	"admin":            {},
	"password":         {},
	"nps":              {},
	"npsnps":           {},
	"changeme":         {},
	"secret":           {},
	"1234567890123456": {},
	"abcdefghijklmnop": {},
}

// 官方默认值与常见填充值，公网可直接解密 /auth/getauthkey 的返回。
var knownWeakAuthCryptKeys = map[string]struct{}{
	"1234567812345678": {},
	"0000000000000000": {},
	"1111111111111111": {},
	"1234567890123456": {},
	"abcdefghijklmnop": {},
}

// ValidateAuthKey 校验配置的 auth_key 是否可用于 web api 签名。
// 未配置、过短、弱口令一律不允许启用 api 认证通道，避免退化成可伪造的固定值。
func ValidateAuthKey(key string) error {
	if key == "" {
		return ErrAuthKeyNotConfigured
	}
	if _, ok := knownWeakAuthKeys[strings.ToLower(key)]; ok {
		return ErrAuthKeyWeak
	}
	if len(key) < AuthKeyMinLength {
		return ErrAuthKeyTooShort
	}
	return nil
}

// ValidateAuthCryptKey 校验 auth_crypt_key 是否可用。
func ValidateAuthCryptKey(key string) error {
	if key == "" {
		return ErrAuthCryptKeyNotConfigured
	}
	if len(key) != AuthCryptKeyLength {
		return ErrAuthCryptKeyLength
	}
	if _, ok := knownWeakAuthCryptKeys[key]; ok {
		return ErrAuthCryptKeyWeak
	}
	return nil
}

// SignAuthKey 计算 web api 请求签名，材料为 timestamp:nonce，
// 输出 hex(HMAC-SHA256(auth_key, timestamp:nonce))。
// 用 HMAC 代替此前的 md5(auth_key+timestamp)，避免密钥与消息拼接后
// 可被长度扩展 / 离线加速爆破；加入 nonce 让每次请求的签名互不相同。
func SignAuthKey(key string, timestamp int64, nonce string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte(":"))
	mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateNonce 校验 nonce 格式，只接受 8 到 64 位可见 ASCII 字符。
func ValidateNonce(nonce string) error {
	if len(nonce) < AuthNonceMinLength || len(nonce) > AuthNonceMaxLength {
		return ErrAuthNonce
	}
	for i := 0; i < len(nonce); i++ {
		if nonce[i] < 0x21 || nonce[i] > 0x7e {
			return ErrAuthNonce
		}
	}
	return nil
}

// VerifyAuthKey 校验 web api 请求签名。
// key 配置非法时直接返回错误，调用方应关闭 api 认证通道而不是放行。
func VerifyAuthKey(key, signature string, timestamp int64, nonce string, now int64) error {
	if err := ValidateAuthKey(key); err != nil {
		return err
	}
	if err := ValidateNonce(nonce); err != nil {
		return err
	}
	if timestamp <= 0 || timestamp-now > AuthTimestampSkew || now-timestamp > AuthTimestampSkew {
		return ErrAuthTimestamp
	}
	provided, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil || len(provided) != sha256.Size {
		return ErrAuthSignature
	}
	expected, err := hex.DecodeString(SignAuthKey(key, timestamp, nonce))
	if err != nil {
		return ErrAuthSignature
	}
	if subtle.ConstantTimeCompare(expected, provided) != 1 {
		return ErrAuthSignature
	}
	return nil
}

// NonceCache 记录时间窗口内用过的 nonce，防止签名请求被原样重放。
type NonceCache struct {
	mu    sync.Mutex
	seen  map[string]int64
	ttl   int64
	count int
}

// NewNonceCache 创建 nonce 缓存，ttl 应不小于签名时间窗口。
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{
		seen: make(map[string]int64),
		ttl:  int64(ttl.Seconds()),
	}
}

// Use 记录 nonce，首次出现返回 true，ttl 内重复出现返回 false。
// 过期项按批次清理，避免每个请求都遍历全表。
func (c *NonceCache) Use(nonce string, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if c.count%256 == 0 {
		for k, expire := range c.seen {
			if expire <= now {
				delete(c.seen, k)
			}
		}
	}
	if expire, ok := c.seen[nonce]; ok && expire > now {
		return false
	}
	c.seen[nonce] = now + c.ttl
	return true
}
