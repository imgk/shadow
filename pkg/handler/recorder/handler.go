package recorder

import (
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/imgk/shadow/pkg/gonet"
)

// netConn is methods shared by net.Conn and gonet.PacketConn
type netConn interface {
	io.Closer
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Conn implements net.Conn and gonet.PacketConn
// and record the number of bytes it reads and writes
type Conn struct {
	netConn
	Reader Reader
	Writer Writer

	preTime  time.Time
	preRead  uint64
	preWrite uint64

	Network       string
	LocalAddress  net.Addr
	RemoteAddress net.Addr
}

// NewConnFromConn is ...
func NewConnFromConn(conn net.Conn, addr net.Addr) (c *Conn) {
	c = &Conn{
		netConn: conn,
		Reader: Reader{
			num:     0,
			conn:    conn,
			pktConn: nil,
		},
		Writer: Writer{
			num:     0,
			conn:    conn,
			pktConn: nil,
		},
		preTime:       time.Now(),
		preRead:       0,
		preWrite:      0,
		Network:       "TCP",
		LocalAddress:  conn.RemoteAddr(),
		RemoteAddress: addr,
	}
	return
}

// NewConnFromPacketConn is ...
func NewConnFromPacketConn(conn gonet.PacketConn) (c *Conn) {
	c = &Conn{
		netConn: conn,
		Reader: Reader{
			num:     0,
			conn:    nil,
			pktConn: conn,
		},
		Writer: Writer{
			num:     0,
			conn:    nil,
			pktConn: conn,
		},
		preTime:       time.Now(),
		preRead:       0,
		preWrite:      0,
		Network:       "UDP",
		LocalAddress:  conn.RemoteAddr(),
		RemoteAddress: conn.LocalAddr(),
	}
	return
}

// Close is ...
func (c *Conn) Close() error {
	c.SetDeadline(time.Now())
	return c.netConn.Close()
}

// Read is ...
func (c *Conn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

// CloseRead is ...
func (c *Conn) CloseRead() error {
	return c.Reader.Close()
}

// Write is ...
func (c *Conn) Write(b []byte) (int, error) {
	return c.Writer.Write(b)
}

// CloseWrite is ...
func (c *Conn) CloseWrite() error {
	return c.Writer.Close()
}

// ReadTo is ...
func (c *Conn) ReadTo(b []byte) (int, net.Addr, error) {
	return c.Reader.ReadTo(b)
}

// WriteFrom is ...
func (c *Conn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return c.Writer.WriteFrom(b, addr)
}

// Nums is ...
func (c *Conn) Nums() (rb uint64, rs uint64, wb uint64, ws uint64) {
	rb = c.Reader.ByteNum()
	wb = c.Writer.ByteNum()

	prev := c.preTime
	c.preTime = time.Now()
	duration := c.preTime.Sub(prev).Seconds()

	rs = uint64(float64(rb-c.preRead) / duration)
	ws = uint64(float64(wb-c.preWrite) / duration)

	c.preRead = rb
	c.preWrite = wb

	return
}

// Handler implements gonet.Handler which can record all active
// connections
type Handler struct {
	// Handler is ...
	gonet.Handler

	mu    sync.RWMutex
	conns map[uint32]*Conn
}

// NewHandler is ...
func NewHandler(h gonet.Handler) *Handler {
	hd := &Handler{
		Handler: h,
		conns:   make(map[uint32]*Conn),
	}
	return hd
}

// Handle is ...
func (h *Handler) Handle(conn net.Conn, addr net.Addr) (err error) {
	key := rand.Uint32()
	conn = NewConnFromConn(conn, addr)

	h.mu.Lock()
	h.conns[key] = conn.(*Conn)
	h.mu.Unlock()

	err = h.Handler.Handle(conn, addr)

	h.mu.Lock()
	delete(h.conns, key)
	h.mu.Unlock()

	return
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) (err error) {
	key := rand.Uint32()
	conn = NewConnFromPacketConn(conn)

	h.mu.Lock()
	h.conns[key] = conn.(*Conn)
	h.mu.Unlock()

	err = h.Handler.HandlePacket(conn)

	h.mu.Lock()
	delete(h.conns, key)
	h.mu.Unlock()

	return
}

// Close is ...
func (h *Handler) Close() (err error) {
	h.mu.Lock()
	for _, c := range h.conns {
		c.Close()
	}
	h.mu.Unlock()
	err = h.Handler.Close()
	return
}
