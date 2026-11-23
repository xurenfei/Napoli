package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astaxie/beego"
	"napoli/lib/crypt"
	"napoli/web/controllers"
	"napoli/web/routers"
)

// probeController 只用于验证 BaseController.Prepare 的放行与拦截。
type probeController struct {
	controllers.BaseController
}

func (c *probeController) Probe() {
	c.Ctx.WriteString("ok")
}

func newProbeServer(t *testing.T) *httptest.Server {
	t.Helper()
	beego.BConfig.RunMode = "prod"
	beego.BConfig.CopyRequestBody = true
	// Prepare 里会读写 session，测试环境需要显式开启并初始化 session manager
	beego.BConfig.WebConfig.Session.SessionOn = true
	initOnce.Do(beego.InitBeforeHTTPRun)
	routers.Init()
	beego.Router("/probe", &probeController{}, "post:Probe")
	return httptest.NewServer(beego.BeeApp.Handlers)
}

var initOnce sync.Once

// noRedirectClient 不跟随跳转，便于断言拦截时返回的 302。
var noRedirectClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func postProbe(t *testing.T, srv *httptest.Server, form url.Values) *http.Response {
	t.Helper()
	resp, err := noRedirectClient.PostForm(srv.URL+"/probe", form)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func TestPrepareRejectsForgedSignature(t *testing.T) {
	if err := beego.AppConfig.Set("auth_key", ""); err != nil {
		t.Fatalf("set config: %v", err)
	}
	srv := newProbeServer(t)
	defer srv.Close()

	now := time.Now().Unix()
	// 旧漏洞利用方式：auth_key 未配置时 md5("" + timestamp) 可被任何人算出
	forged := crypt.Md5(strconv.FormatInt(now, 10))
	resp := postProbe(t, srv, url.Values{
		"auth_key":  {forged},
		"timestamp": {strconv.FormatInt(now, 10)},
		"nonce":     {"forged-nonce-0001"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("forged signature with empty auth_key: got %d, want 302", resp.StatusCode)
	}
}

func TestGetAuthKeyFromRemoteDenied(t *testing.T) {
	if err := beego.AppConfig.Set("auth_key", "0f9a2c7d4e6b8a1c9d3e5f7a2b4c6d8e"); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if err := beego.AppConfig.Set("auth_crypt_key", "8c1f4a7d2e9b6c30"); err != nil {
		t.Fatalf("set config: %v", err)
	}
	srv := newProbeServer(t)
	defer srv.Close()

	call := func(addr string, header map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/getauthkey", nil)
		req.RemoteAddr = addr
		for k, v := range header {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		beego.BeeApp.Handlers.ServeHTTP(w, req)
		return w
	}

	remote := call("203.0.113.5:54321", nil)
	if !strings.Contains(remote.Body.String(), "permission denied") {
		t.Fatalf("remote caller should be denied, got %s", remote.Body.String())
	}

	// 伪造 X-Forwarded-For 不能绕过本机判断
	spoofed := call("203.0.113.5:54321", map[string]string{"X-Forwarded-For": "127.0.0.1"})
	if !strings.Contains(spoofed.Body.String(), "permission denied") {
		t.Fatalf("spoofed X-Forwarded-For should not bypass, got %s", spoofed.Body.String())
	}

	local := call("127.0.0.1:54321", nil)
	if !strings.Contains(local.Body.String(), `"status":1`) {
		t.Fatalf("local caller should get the key, got %s", local.Body.String())
	}
}

func TestPrepareAcceptsHMAC(t *testing.T) {
	key := "0f9a2c7d4e6b8a1c9d3e5f7a2b4c6d8e"
	if err := beego.AppConfig.Set("auth_key", key); err != nil {
		t.Fatalf("set config: %v", err)
	}
	srv := newProbeServer(t)
	defer srv.Close()

	now := time.Now().Unix()
	good := strconv.FormatInt(now, 10)
	nonce := "accept-nonce-" + good
	form := url.Values{
		"auth_key":  {crypt.SignAuthKey(key, now, nonce)},
		"timestamp": {good},
		"nonce":     {nonce},
	}
	resp := postProbe(t, srv, form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid signature: got %d, want 200", resp.StatusCode)
	}

	// 同一 nonce 原样重放必须被拒
	resp2 := postProbe(t, srv, form)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("replayed request: got %d, want 302", resp2.StatusCode)
	}

	// 同一套参数把签名换掉必须被拒
	resp3 := postProbe(t, srv, url.Values{
		"auth_key":  {crypt.SignAuthKey(key, now, "other-nonce-"+good)},
		"timestamp": {good},
		"nonce":     {nonce},
	})
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusFound {
		t.Fatalf("mismatched signature: got %d, want 302", resp3.StatusCode)
	}
}
