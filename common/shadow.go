package common

import (
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/multierr"
)

const MaxBufferSize = 16384

var byteBuffer = sync.Pool{New: newBuffer}

func newBuffer() interface{} {
	b := make([]byte, MaxBufferSize)
	// Return a *[]byte instead of []byte ensures that
	// the []byte is not copied, which would cause a heap
	// allocation on every call to sync.pool.Put
	return &b
}

func Get() LazySlice {
	p := byteBuffer.Get().(*[]byte)
	return LazySlice{Pointer: p}
}

func Put(b LazySlice) {
	byteBuffer.Put(b.Pointer)
	b.Pointer = nil
}

type LazySlice struct {
	Pointer *[]byte
}

func (s LazySlice) Get() []byte {
	return *s.Pointer
}

type Device interface {
	io.Closer
	io.Writer
	io.WriterTo
}

type Handler interface {
	io.Closer
	Handle(net.Conn, net.Addr) error
	HandlePacket(PacketConn) error
}

type PacketConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	ReadTo([]byte) (int, net.Addr, error)
	WriteFrom([]byte, net.Addr) (int, error)
	Close() error
}

type CloseReader interface {
	CloseRead() error
}

type CloseWriter interface {
	CloseWrite() error
}

type DuplexConn interface {
	net.Conn
	CloseReader
	CloseWriter
}

type duplexConn struct {
	net.Conn
}

func (c duplexConn) ReadFrom(r io.Reader) (int64, error) {
	return Copy(c.Conn, r)
}

func (c duplexConn) WriteTo(w io.Writer) (int64, error) {
	return Copy(w, c.Conn)
}

func (c duplexConn) CloseRead() error {
	if close, ok := c.Conn.(CloseReader); ok {
		return close.CloseRead()
	}

	return c.Conn.Close()
}

func (c duplexConn) CloseWrite() error {
	if close, ok := c.Conn.(CloseWriter); ok {
		return close.CloseWrite()
	}

	return c.Conn.Close()
}

func Relay(c, rc net.Conn) error {
	l, ok := c.(DuplexConn)
	if !ok {
		l = duplexConn{Conn: c}
	}

	r, ok := rc.(DuplexConn)
	if !ok {
		r = duplexConn{Conn: rc}
	}

	return relay(l, r)
}

func relay(c, rc DuplexConn) error {
	errCh := make(chan error, 1)
	go relay2(c, rc, errCh)

	_, err := Copy(c, rc)
	if err != nil {
		c.Close()
		rc.Close()
	} else {
		c.CloseWrite()
		rc.CloseRead()
	}

	return multierr.Combine(err, <-errCh)
}

func relay2(c, rc DuplexConn, errCh chan error) {
	_, err := Copy(rc, c)
	if err != nil {
		rc.Close()
		c.Close()
	} else {
		rc.CloseWrite()
		c.CloseRead()
	}

	errCh <- err
}

func Copy(w io.Writer, r io.Reader) (n int64, err error) {
	if c, ok := r.(duplexConn); ok {
		r = c.Conn
	}
	if c, ok := w.(duplexConn); ok {
		w = c.Conn
	}
	if wt, ok := r.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	if rt, ok := w.(io.ReaderFrom); ok {
		if _, ok := rt.(*net.TCPConn); !ok {
			return rt.ReadFrom(r)
		}
	}

	slice := Get()
	defer Put(slice)
	b := slice.Get()

	for {
		nr, er := r.Read(b)
		if nr > 0 {
			nw, ew := w.Write(b[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return n, err
}
