package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"time"
)

var (
	cert tls.Certificate
)

func InitTls() {
	c, k, err := generateKeyPair("NPS Org")
	if err == nil {
		cert, err = tls.X509KeyPair(c, k)
	}
	if err != nil {
		log.Fatalln("Error initializing crypto certs", err)
	}
}

// minTLSVersion 是隧道内层 TLS 允许的最低协议版本。
// TLS 1.0/1.1 已被主流浏览器与 RFC 8996 弃用，且 Go 1.22 起标准库默认最低即为 1.2。
// 这里显式声明，避免依赖工具链默认值，同时在项目仍使用 Go 1.21 时也生效。
const minTLSVersion = tls.VersionTLS12

func NewTlsServerConn(conn net.Conn) net.Conn {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minTLSVersion,
	}
	return tls.Server(conn, config)
}

// NewTlsClientConn 建立隧道内层 TLS 连接。
// 服务端证书是每次启动现场生成的自签证书，客户端无法用系统根证书链验证，
// 因此这里跳过证书校验，身份认证由上层 vkey 完成。若将来改为持久化证书，
// 应在此处改用证书指纹固定（pinning）替代 InsecureSkipVerify。
func NewTlsClientConn(conn net.Conn) net.Conn {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         minTLSVersion,
	}
	return tls.Client(conn, conf)
}

func generateKeyPair(CommonName string) (rawCert, rawKey []byte, err error) {
	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 10 // ten years
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Company Name LTD."},
			CommonName:   CommonName,
			Country:      []string{"US"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return
}
