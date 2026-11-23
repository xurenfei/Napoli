package controllers

import (
	"encoding/hex"
	"net"
	"time"

	"ehang.io/nps/lib/crypt"
	"github.com/astaxie/beego"
)

type AuthController struct {
	beego.Controller
}

func (s *AuthController) GetAuthKey() {
	m := make(map[string]interface{})
	defer func() {
		s.Data["json"] = m
		s.ServeJSON()
	}()
	// 加密后的 auth_key 等同于凭据本身。此前该接口对任何来源开放，
	// 攻击者可以拉取密文后离线爆破 auth_crypt_key 还原 auth_key，
	// 这里限制为本机或已登录管理员。
	// 注意不能使用 Ctx.Input.IP()，它优先读 X-Forwarded-For，可被伪造。
	if !isLocalAddr(s.Ctx.Request.RemoteAddr) && s.GetSession("isAdmin") != true {
		m["status"] = 0
		m["msg"] = "permission denied"
		return
	}
	cryptKey := beego.AppConfig.String("auth_crypt_key")
	if err := crypt.ValidateAuthCryptKey(cryptKey); err != nil {
		m["status"] = 0
		m["msg"] = err.Error()
		return
	}
	b, err := crypt.AesEncrypt([]byte(beego.AppConfig.String("auth_key")), []byte(cryptKey))
	if err != nil {
		m["status"] = 0
		m["msg"] = err.Error()
		return
	}
	m["status"] = 1
	m["crypt_auth_key"] = hex.EncodeToString(b)
	m["crypt_type"] = "aes cbc"
}

func (s *AuthController) GetTime() {
	m := make(map[string]interface{})
	m["time"] = time.Now().Unix()
	s.Data["json"] = m
	s.ServeJSON()
}

// isLocalAddr 判断连接来源是否为本机回环地址，只认 RemoteAddr。
func isLocalAddr(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
