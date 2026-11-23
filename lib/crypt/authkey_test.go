package crypt

import (
	"strings"
	"testing"
	"time"
)

func TestValidateAuthKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want error
	}{
		{"empty", "", ErrAuthKeyNotConfigured},
		{"official example", "test", ErrAuthKeyWeak},
		{"too short", "shortkey", ErrAuthKeyTooShort},
		{"weak 16", "1234567890123456", ErrAuthKeyWeak},
		{"valid", "0f9a2c7d4e6b8a1c", nil},
	}
	for _, c := range cases {
		if got := ValidateAuthKey(c.key); got != c.want {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestValidateAuthCryptKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want error
	}{
		{"empty", "", ErrAuthCryptKeyNotConfigured},
		{"short", "123456", ErrAuthCryptKeyLength},
		{"official default", "1234567812345678", ErrAuthCryptKeyWeak},
		{"valid", "8c1f4a7d2e9b6c30", nil},
	}
	for _, c := range cases {
		if got := ValidateAuthCryptKey(c.key); got != c.want {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestVerifyAuthKey(t *testing.T) {
	key := "0f9a2c7d4e6b8a1c"
	now := time.Now().Unix()
	nonce := "a1b2c3d4e5f60718"

	if err := VerifyAuthKey(key, SignAuthKey(key, now, nonce), now, nonce, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// 空 auth_key 时不能退化成可预测签名
	if err := VerifyAuthKey("", SignAuthKey("", now, nonce), now, nonce, now); err == nil {
		t.Fatal("empty auth_key must not pass verification")
	}
	// 弱口令即使签名正确也要拒绝
	if err := VerifyAuthKey("test", SignAuthKey("test", now, nonce), now, nonce, now); err == nil {
		t.Fatal("weak auth_key must not pass verification")
	}
	// nonce 缺失
	if err := VerifyAuthKey(key, SignAuthKey(key, now, ""), now, "", now); err != ErrAuthNonce {
		t.Fatalf("empty nonce: got %v", err)
	}
	// 篡改签名
	bad := strings.Repeat("0", len(SignAuthKey(key, now, nonce)))
	if err := VerifyAuthKey(key, bad, now, nonce, now); err != ErrAuthSignature {
		t.Fatalf("tampered signature: got %v", err)
	}
	// 超出时间窗口
	stale := now - AuthTimestampSkew - 1
	if err := VerifyAuthKey(key, SignAuthKey(key, stale, nonce), stale, nonce, now); err != ErrAuthTimestamp {
		t.Fatalf("stale timestamp: got %v", err)
	}
	// nonce 与时间戳绑定，换时间戳不能复用
	if err := VerifyAuthKey(key, SignAuthKey(key, now, nonce), now+1, nonce, now); err != ErrAuthSignature {
		t.Fatalf("nonce bound to timestamp: got %v", err)
	}
}

func TestNonceCache(t *testing.T) {
	cache := NewNonceCache(60 * time.Second)
	now := time.Now().Unix()

	if !cache.Use("nonce-0001", now) {
		t.Fatal("first use should pass")
	}
	if cache.Use("nonce-0001", now+1) {
		t.Fatal("replayed nonce should be rejected")
	}
	if !cache.Use("nonce-0002", now+1) {
		t.Fatal("different nonce should pass")
	}
	if !cache.Use("nonce-0001", now+61) {
		t.Fatal("nonce should be reusable after ttl")
	}
}
