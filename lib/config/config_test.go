package config

import (
	"log"
	"regexp"
	"testing"
)

func TestReg(t *testing.T) {
	content := `
[common]
server=127.0.0.1:8284
tp=tcp
vkey=123
[web2]
host=www.baidu.com
host_change=www.sina.com
target=127.0.0.1:8080,127.0.0.1:8082
header_cookkile=122123
header_user-Agent=122123
[web2]
host=www.baidu.com
host_change=www.sina.com
target=127.0.0.1:8080,127.0.0.1:8082
header_cookkile="122123"
header_user-Agent=122123
[tunnel1]
type=udp
target=127.0.0.1:8080
port=9001
compress=snappy
crypt=true
u=1
p=2
[tunnel2]
type=tcp
target=127.0.0.1:8080
port=9001
compress=snappy
crypt=true
u=1
p=2
`
	re, err := regexp.Compile(`\[.+?\]`)
	if err != nil {
		t.Fail()
	}
	log.Println(re.FindAllString(content, -1))
}

func TestDealCommon(t *testing.T) {
	// 字段名需与 dealCommon 及 conf/npc.conf 保持一致：
	// 配置键早已从 server/tp 改为 server_addr/conn_type，此处原先未同步，导致用例恒失败。
	s := `server_addr=127.0.0.1:8284
conn_type=tcp
vkey=123`
	c := dealCommon(s)
	// 逐字段比对：dealCommon 会预置 Client/Cnf 等指针字段，
	// 整体比较 *c != *f 必然不等，原写法实际测不出任何东西。
	if c.Server != "127.0.0.1:8284" {
		t.Fatalf("Server = %q, want 127.0.0.1:8284", c.Server)
	}
	if c.Tp != "tcp" {
		t.Fatalf("Tp = %q, want tcp", c.Tp)
	}
	if c.VKey != "123" {
		t.Fatalf("VKey = %q, want 123", c.VKey)
	}
}

func TestGetTitleContent(t *testing.T) {
	s := "[common]"
	if getTitleContent(s) != "common" {
		t.Fail()
	}
}
