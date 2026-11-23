package pmux

import (
	"net"
	"time"
)

type PortConn struct {
	Conn     net.Conn
	rs       []byte
	readMore bool
	start    int
}

func newPortConn(conn net.Conn, rs []byte, readMore bool) *PortConn {
	return &PortConn{
		Conn:     conn,
		rs:       rs,
		readMore: readMore,
	}
}

func (pConn *PortConn) Read(b []byte) (n int, err error) {
	// 缓冲区装不完剩余的识别字节时只回填一部分。
	// 原实现从 rs 头部拷贝而不是从 start 处拷贝，短读会把已发出的前缀重复吐出，
	// 上层据此解析握手内容就会错位。
	if remaining := len(pConn.rs) - pConn.start; len(b) < remaining {
		n = copy(b, pConn.rs[pConn.start:])
		pConn.start += n
		return n, nil
	}
	if pConn.start < len(pConn.rs) {
		defer func() {
			pConn.start = len(pConn.rs)
		}()
		n = copy(b, pConn.rs[pConn.start:])
		if !pConn.readMore {
			return
		}
	}
	var n2 = 0
	n2, err = pConn.Conn.Read(b[n:])
	n = n + n2
	return
}

func (pConn *PortConn) Write(b []byte) (n int, err error) {
	return pConn.Conn.Write(b)
}

func (pConn *PortConn) Close() error {
	return pConn.Conn.Close()
}

func (pConn *PortConn) LocalAddr() net.Addr {
	return pConn.Conn.LocalAddr()
}

func (pConn *PortConn) RemoteAddr() net.Addr {
	return pConn.Conn.RemoteAddr()
}

func (pConn *PortConn) SetDeadline(t time.Time) error {
	return pConn.Conn.SetDeadline(t)
}

func (pConn *PortConn) SetReadDeadline(t time.Time) error {
	return pConn.Conn.SetReadDeadline(t)
}

func (pConn *PortConn) SetWriteDeadline(t time.Time) error {
	return pConn.Conn.SetWriteDeadline(t)
}
