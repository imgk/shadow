package recorder

import (
	"errors"
	"net"
	"sync/atomic"

	"github.com/imgk/shadow/pkg/gonet"
)

// Writer implements net.Conn.Write and gonet.PacketConn.WriteFrom
// and record the number of bytes
type Writer struct {
	num     uint64
	conn    net.Conn
	pktConn gonet.PacketConn
}

// Write is ...
func (w *Writer) Write(b []byte) (n int, err error) {
	n, err = w.conn.Write(b)
	atomic.AddUint64(&w.num, uint64(n))
	return
}

// Close is ...
func (w *Writer) Close() error {
	if closer, ok := w.conn.(gonet.CloseWriter); ok {
		return closer.CloseWrite()
	}
	return errors.New("not supported")
}

// WriteFrom is ...
func (w *Writer) WriteFrom(b []byte, addr net.Addr) (n int, err error) {
	n, err = w.pktConn.WriteFrom(b, addr)
	atomic.AddUint64(&w.num, uint64(n))
	return
}

// ByteNum is ...
func (w *Writer) ByteNum() uint64 {
	return atomic.LoadUint64(&w.num)
}
