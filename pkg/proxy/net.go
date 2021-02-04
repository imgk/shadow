package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/socks"
)

var (
	_ net.Listener     = (*Listener)(nil)
	_ net.Conn         = (*Conn)(nil)
	_ gonet.DuplexConn = (*Conn)(nil)
	_ gonet.PacketConn = (*PacketConn)(nil)
)

// Listener is ...
// net.Listener
// accept connections bypassed by Server.handshake
type Listener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
}

// NewListener is ...
func NewListener(addr net.Addr) *Listener {
	ln := &Listener{
		addr:   addr,
		conns:  make(chan net.Conn, 5),
		closed: make(chan struct{}),
	}
	return ln
}

// Accept is ...
func (s *Listener) Accept() (net.Conn, error) {
	select {
	case <-s.closed:
	case conn := <-s.conns:
		return conn, nil
	}
	return nil, os.ErrClosed
}

// Receive is ...
func (s *Listener) Receive(conn net.Conn) {
	select {
	case <-s.closed:
	case s.conns <- conn:
	}
}

// Close is ...
func (s *Listener) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	return nil
}

// Addr is ...
func (s *Listener) Addr() net.Addr {
	return s.addr
}

// Conn is ...
type Conn struct {
	net.Conn
	Reader *bytes.Reader
}

// NewConn is ...
func NewConn(conn net.Conn, r *bytes.Reader) *Conn {
	c := &Conn{Conn: conn, Reader: r}
	return c
}

// CloseRead is ...
func (c *Conn) CloseRead() error {
	if close, ok := c.Conn.(gonet.CloseReader); ok {
		return close.CloseRead()
	}
	return errors.New("not supported")
}

// CloseWrite is ...
func (c *Conn) CloseWrite() error {
	if close, ok := c.Conn.(gonet.CloseWriter); ok {
		return close.CloseWrite()
	}
	return errors.New("not supported")
}

// Read is ...
func (c *Conn) Read(b []byte) (int, error) {
	if c.Reader == nil {
		return c.Conn.Read(b)
	}
	n, err := c.Reader.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			c.Reader = nil
			err = nil
		}
	}
	return n, err
}

// PacketConn is ...
// gonet.PacketConn
type PacketConn struct {
	*net.UDPConn
	addr net.Addr
}

// NewPacketConn is ...
func NewPacketConn(src net.Addr, conn *net.UDPConn) *PacketConn {
	c := &PacketConn{UDPConn: conn, addr: src}
	return c
}

// RemoteAddr is ...
func (c *PacketConn) RemoteAddr() net.Addr {
	return c.addr
}

// ReadTo is ...
func (c *PacketConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	const MaxBufferSize = 16 << 10
	sc, buf := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

	n, err = c.UDPConn.Read(buf)
	if err != nil {
		return
	}
	tgt, err := socks.ParseAddr(buf[3:])
	if err != nil {
		return
	}
	addr = &socks.Addr{Addr: append(make([]byte, 0, len(tgt.Addr)), tgt.Addr...)}
	n = copy(b, buf[3+len(tgt.Addr):n])
	return
}

// WriteFrom is ...
func (c *PacketConn) WriteFrom(b []byte, addr net.Addr) (n int, err error) {
	const MaxBufferSize = 16 << 10
	sc, buf := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

	src, err := socks.ResolveAddrBuffer(addr, b[3:])
	if err != nil {
		return
	}
	n = copy(buf[3+len(src.Addr):], b)
	_, err = c.UDPConn.Write(buf[:3+len(src.Addr)+n])
	return
}
