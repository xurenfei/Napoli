package install

import "testing"

// TestAutoUpdateDisabled 守住自动更新开关。
//
// 这个开关关闭是有意的：旧通道从 ehang.io 拉取未签名的压缩包，解包后直接覆盖安装位置的可执行文件，
// 而上游项目已停止维护，域名不在本项目控制之下。若要把开关改回 true，必须同时满足两点：
// 发布源指向本项目自己的发布通道，且下载内容有可验证的签名或摘要比对。
// 改之前先改这个用例，让改动显式地经过一次确认。
func TestAutoUpdateDisabled(t *testing.T) {
	if autoUpdateEnabled {
		t.Fatal("autoUpdateEnabled 为 true：在接入可信发布源与签名校验之前不应放开自动更新")
	}
}
