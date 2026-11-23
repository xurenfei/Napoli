package pmux

import (
	"errors"
	"net"
	"sync/atomic"
)

type PortListener struct {
	net.Listener
	connCh  chan *PortConn
	addr    net.Addr
	done    <-chan struct{}
	isClose atomic.Bool
}

// NewPortListener 的 done 来自 PortMux 的关闭信号。
// Accept 同时等待 done 与 connCh，这样 PortMux 关闭时不必 close 数据通道，
// 也就不会出现「分发方正往已关闭的 channel 发送」的 panic。
func NewPortListener(connCh chan *PortConn, addr net.Addr, done <-chan struct{}) *PortListener {
	return &PortListener{
		connCh: connCh,
		addr:   addr,
		done:   done,
	}
}

func (pListener *PortListener) Accept() (net.Conn, error) {
	if pListener.isClose.Load() {
		return nil, errors.New("the listener has closed")
	}
	select {
	case <-pListener.done:
		return nil, errors.New("the listener has closed")
	case conn := <-pListener.connCh:
		if conn != nil {
			return conn, nil
		}
		return nil, errors.New("the listener has closed")
	}
}

func (pListener *PortListener) Close() error {
	if pListener.isClose.Swap(true) {
		return errors.New("the listener has closed")
	}
	return nil
}

func (pListener *PortListener) Addr() net.Addr {
	return pListener.addr
}
