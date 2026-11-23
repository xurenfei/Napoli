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

	if err := VerifyAuthKey(key, SignAuthKey(key, now), now, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// 空 auth_key 时不能退化成可预测签名
	if err := VerifyAuthKey("", SignAuthKey("", now), now, now); err == nil {
		t.Fatal("empty auth_key must not pass verification")
	}
	// 弱口令即使签名正确也要拒绝
	if err := VerifyAuthKey("test", SignAuthKey("test", now), now, now); err == nil {
		t.Fatal("weak auth_key must not pass verification")
	}
	// 篡改签名
	bad := SignAuthKey(key, now)
	bad = strings.Repeat("0", len(bad))
	if err := VerifyAuthKey(key, bad, now, now); err != ErrAuthSignature {
		t.Fatalf("tampered signature: got %v", err)
	}
	// 超出时间窗口
	if err := VerifyAuthKey(key, SignAuthKey(key, now-AuthTimestampSkew-1), now-AuthTimestampSkew-1, now); err != ErrAuthTimestamp {
		t.Fatalf("stale timestamp: got %v", err)
	}
}
