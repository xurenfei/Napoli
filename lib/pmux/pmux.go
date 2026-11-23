// This module is used for port reuse
// Distinguish client, web manager , HTTP and HTTPS according to the difference of protocol
package pmux

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/astaxie/beego/logs"
	"napoli/lib/common"
)

const (
	HTTP_GET     = 716984
	HTTP_POST    = 807983
	HTTP_HEAD    = 726965
	HTTP_PUT     = 808585
	HTTP_DELETE  = 686976
	HTTP_CONNECT = 677978
	HTTP_OPTIONS = 798084
	HTTP_TRACE   = 848265
	CLIENT       = 848384
	// 原值是不带单位的 10，传给 time.NewTimer 时会被当成 10 纳秒，
	// 于是连接刚分好类定时器就已到期，select 随机选中超时分支，
	// 连接既没被分发也没被关闭，客户端只能一直等到自己的读超时。
	ACCEPT_TIME_OUT = 10 * time.Second
)

type PortMux struct {
	net.Listener
	port        int
	isClose     atomic.Bool
	closeOnce   sync.Once
	closeErr    error
	done        chan struct{}
	managerHost string
	clientConn  chan *PortConn
	httpConn    chan *PortConn
	httpsConn   chan *PortConn
	managerConn chan *PortConn
}

func NewPortMux(port int, managerHost string) *PortMux {
	pMux := &PortMux{
		managerHost: managerHost,
		port:        port,
		done:        make(chan struct{}),
		clientConn:  make(chan *PortConn),
		httpConn:    make(chan *PortConn),
		httpsConn:   make(chan *PortConn),
		managerConn: make(chan *PortConn),
	}
	pMux.Start()
	return pMux
}

func (pMux *PortMux) Start() error {
	// Port multiplexing is based on TCP only
	tcpAddr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:"+strconv.Itoa(pMux.port))
	if err != nil {
		return err
	}
	pMux.Listener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		logs.Error(err)
		// 端口复用监听失败则整个入口不可用，以非零码退出便于服务管理器识别。
		os.Exit(1)
	}
	go func() {
		for {
			conn, err := pMux.Listener.Accept()
			if err != nil {
				logs.Warn(err)
				// 监听已关闭或出错时必须退出循环。
				// 原实现不 return，会带着 nil 连接继续调 process 并空转，
				// 表现为 nil 指针 panic 加无限循环关闭同一个 listener。
				pMux.Close()
				return
			}
			go pMux.process(conn)
		}
	}()
	return nil
}

func (pMux *PortMux) process(conn net.Conn) {
	// Recognition according to different signs
	// read 3 byte
	buf := make([]byte, 3)
	if n, err := io.ReadFull(conn, buf); err != nil || n != 3 {
		return
	}
	var ch chan *PortConn
	var rs []byte
	var buffer bytes.Buffer
	var readMore = false
	switch common.BytesToNum(buf) {
	case HTTP_CONNECT, HTTP_DELETE, HTTP_GET, HTTP_HEAD, HTTP_OPTIONS, HTTP_POST, HTTP_PUT, HTTP_TRACE: //http and manager
		buffer.Reset()
		r := bufio.NewReader(conn)
		buffer.Write(buf)
		for {
			b, _, err := r.ReadLine()
			if err != nil {
				logs.Warn("read line error", err.Error())
				conn.Close()
				break
			}
			buffer.Write(b)
			buffer.Write([]byte("\r\n"))
			if strings.Index(string(b), "Host:") == 0 || strings.Index(string(b), "host:") == 0 {
				// Remove host and space effects
				str := strings.Replace(string(b), "Host:", "", -1)
				str = strings.Replace(str, "host:", "", -1)
				str = strings.TrimSpace(str)
				// Determine whether it is the same as the manager domain name
				if common.GetIpByAddr(str) == pMux.managerHost {
					ch = pMux.managerConn
				} else {
					ch = pMux.httpConn
				}
				b, _ := r.Peek(r.Buffered())
				buffer.Write(b)
				rs = buffer.Bytes()
				break
			}
		}
	case CLIENT: // client connection
		ch = pMux.clientConn
	default: // https
		readMore = true
		ch = pMux.httpsConn
	}
	if len(rs) == 0 {
		rs = buf
	}
	timer := time.NewTimer(ACCEPT_TIME_OUT)
	defer timer.Stop()
	select {
	case <-pMux.done:
		// 复用器已关闭，没有监听方还会来取连接，直接关掉避免 fd 泄漏。
		conn.Close()
	case <-timer.C:
		// 超时仍无人接收，说明对应服务未启动（如未配 https 端口），
		// 必须关闭连接，否则对端会一直挂到自己的超时。
		conn.Close()
	case ch <- newPortConn(conn, rs, readMore):
	}
}

func (pMux *PortMux) Close() error {
	// 关闭动作会被多方并发触发（Accept 循环出错、外部主动关闭、进程退出），
	// 原实现无同步，两次 Close 会重复 close 同一个 channel 直接 panic。
	pMux.closeOnce.Do(func() {
		pMux.isClose.Store(true)
		// 只广播关闭信号，不关闭四个分发 channel。
		// 分发方可能正阻塞在 ch <- 上，关闭 channel 会触发 send on closed channel；
		// PortListener 已改为同时监听 done，因此无需再靠关闭 channel 唤醒。
		close(pMux.done)
		pMux.closeErr = pMux.Listener.Close()
	})
	return pMux.closeErr
}

func (pMux *PortMux) GetClientListener() net.Listener {
	return NewPortListener(pMux.clientConn, pMux.Listener.Addr(), pMux.done)
}

func (pMux *PortMux) GetHttpListener() net.Listener {
	return NewPortListener(pMux.httpConn, pMux.Listener.Addr(), pMux.done)
}

func (pMux *PortMux) GetHttpsListener() net.Listener {
	return NewPortListener(pMux.httpsConn, pMux.Listener.Addr(), pMux.done)
}

func (pMux *PortMux) GetManagerListener() net.Listener {
	return NewPortListener(pMux.managerConn, pMux.Listener.Addr(), pMux.done)
}
