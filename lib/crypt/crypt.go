package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
)

// en
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// de
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	err, origData = PKCS5UnPadding(origData)
	return origData, err
}

// Completion when the length is insufficient
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// Remove excess
// PKCS5UnPadding 去掉 CBC 解密后的填充字节。
// 原实现直接取最后一个字节作为填充长度，密文为空或长度非法时会让切片越界 panic。
// 解密内容来自对端（隧道内可能已被篡改），必须在切片前做完边界校验。
func PKCS5UnPadding(origData []byte) (error, []byte) {
	length := len(origData)
	if length == 0 {
		return errors.New("empty ciphertext"), nil
	}
	unpadding := int(origData[length-1])
	if unpadding == 0 || unpadding > aes.BlockSize || unpadding > length {
		return errors.New("invalid padding"), nil
	}
	return nil, origData[:(length - unpadding)]
}

// Generate 32-bit MD5 strings
// Md5 仅保留给既有协议使用（vkey 校验值、p2p 口令摘要），对端按同样算法比对，
// 改算法会直接断连。新代码不要用它做口令存储或完整性校验。
func Md5(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// Generating Random Verification Key
// GetRandomString 生成客户端身份标识 VerifyKey。
// 原实现用 math/rand 并以纳秒时间戳播种，种子熵极低，攻击者掌握大致启动时间
// 即可推算出全部 VerifyKey，等于伪造任意客户端身份。这里改用 crypto/rand，
// 并以拒绝采样消除取模偏差。
func GetRandomString(l int) string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	const limit = 256 - (256 % len(chars)) // 拒绝采样上界，避免取模偏斜
	if l <= 0 {
		return ""
	}
	result := make([]byte, 0, l)
	buf := make([]byte, l*2)
	for len(result) < l {
		if _, err := cryptorand.Read(buf); err != nil {
			// 系统熵源不可用时宁可启动失败，也不要退回到可预测的伪随机序列。
			panic("crypto/rand unavailable: " + err.Error())
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			result = append(result, chars[int(b)%len(chars)])
			if len(result) == l {
				break
			}
		}
	}
	return string(result)
}
