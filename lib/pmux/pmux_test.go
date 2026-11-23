package pmux

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/astaxie/beego/logs"
)

func TestPortMux_Close(t *testing.T) {
	logs.Reset()
	logs.EnableFuncCallDepth(true)
	logs.SetLogFuncCallDepth(3)

	// 端口传 0 由内核分配，避免与其它进程或并行测试抢固定端口。
	// NewPortMux 内部已经调用了 Start()，原测试又起一个 goroutine 重复 Start，
	// 同一个端口二次 bind 必然失败，而 Start 失败会直接 os.Exit，
	// 整个测试包因此崩溃。这里只验证能正常创建并关闭。
	pMux := NewPortMux(0, "Ds")
	if pMux.Listener == nil {
		t.Fatal("listener should be initialized after NewPortMux")
	}
	if err := pMux.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// 关闭必须可重入：Accept 循环出错和进程退出会并发触发 Close。
	if err := pMux.Close(); err != nil {
		t.Fatalf("second Close() should not fail, got %v", err)
	}
}

// TestPortConn_ShortReadReplay 覆盖识别字节的短读回放。
// 当上层用小于剩余回放长度的缓冲区读取时，必须从上次读到的位置继续，
// 原实现每次都从缓冲区头部拷贝，会把已读过的字节重复吐出。
func TestPortConn_ShortReadReplay(t *testing.T) {
	pConn := newPortConn(nil, []byte("TST"), false)
	var got []byte
	buf := make([]byte, 1)
	for i := 0; i < 3; i++ {
		n, err := pConn.Read(buf)
		if err != nil {
			t.Fatalf("read %d error %v", i, err)
		}
		if n != 1 {
			t.Fatalf("read %d got n=%d, want 1", i, n)
		}
		got = append(got, buf[0])
	}
	if string(got) != "TST" {
		t.Fatalf("replayed bytes = %q, want %q", string(got), "TST")
	}
}

// TestPortMux_RoutesClientConn 覆盖「客户端握手连接必须完整送达监听方」。
// 历史上 ACCEPT_TIME_OUT 被写成无单位的 10，time.NewTimer 按 10 纳秒处理，
// 定时器在 select 前就已到期，于是约一半连接被静默丢弃（且不关闭）。
// 单次往返测不出来，因此这里连打 50 次，要求全部成功。
func TestPortMux_RoutesClientConn(t *testing.T) {
	pMux := NewPortMux(0, "manager.test")
	defer pMux.Close()

	clientListener := pMux.GetClientListener()
	addr := pMux.Listener.Addr().String()

	const rounds = 50
	for i := 0; i < rounds; i++ {
		clientErr := make(chan error, 1)
		go func() {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				clientErr <- err
				return
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("TST")); err != nil {
				clientErr <- err
				return
			}
			// 稍微保持连接，避免在分发完成前就断开。
			time.Sleep(5 * time.Millisecond)
			clientErr <- nil
		}()

		accepted := make(chan net.Conn, 1)
		go func() {
			conn, err := clientListener.Accept()
			if err != nil {
				accepted <- nil
				return
			}
			accepted <- conn
		}()

		var conn net.Conn
		select {
		case conn = <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: Accept timed out, connection was dropped", i)
		}
		if conn == nil {
			t.Fatalf("round %d: Accept returned error", i)
		}

		// 分发时必须把用于识别的 3 字节原样回放，否则上层读到的握手内容会错位。
		head := make([]byte, 3)
		if _, err := io.ReadFull(conn, head); err != nil {
			t.Fatalf("round %d: read head error %v", i, err)
		}
		if string(head) != "TST" {
			t.Fatalf("round %d: head = %q, want %q", i, string(head), "TST")
		}
		conn.Close()

		if err := <-clientErr; err != nil {
			t.Fatalf("round %d: client error %v", i, err)
		}
	}
}
