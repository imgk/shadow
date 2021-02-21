package recorder

import (
	"errors"
	"net"
	"sync/atomic"

	"github.com/imgk/shadow/pkg/gonet"
)

// Reader implements net.Conn.Read and gonet.PacketConn.ReadTo
// and record the number of bytes
type Reader struct {
	num     uint64
	conn    net.Conn
	pktConn gonet.PacketConn
}

// Read is ...
func (r *Reader) Read(b []byte) (n int, err error) {
	n, err = r.conn.Read(b)
	atomic.AddUint64(&r.num, uint64(n))
	return
}

// Close is ...
func (r *Reader) Close() error {
	if closer, ok := r.conn.(gonet.CloseReader); ok {
		return closer.CloseRead()
	}
	return errors.New("not supported")
}

// ReadTo is ...
func (r *Reader) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = r.pktConn.ReadTo(b)
	atomic.AddUint64(&r.num, uint64(n))
	return
}

// ByteNum is ...
func (r *Reader) ByteNum() uint64 {
	return atomic.LoadUint64(&r.num)
}
