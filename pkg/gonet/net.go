package gonet

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/xerror"
)

// Handler is ...
type Handler interface {
	io.Closer
	Handle(net.Conn, net.Addr) error
	HandlePacket(PacketConn) error
}

// PacketConn is ...
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

// CloseReader is ...
type CloseReader interface {
	CloseRead() error
}

// CloseWriter
type CloseWriter interface {
	CloseWrite() error
}

// DuplexConn
type DuplexConn interface {
	net.Conn
	CloseReader
	CloseWriter
}

// WrapDuplexConn is ...
func WrapDuplexConn(conn net.Conn) DuplexConn {
	if c, ok := conn.(DuplexConn); ok {
		return c
	}
	return &duplexConn{Conn: conn}
}

type duplexConn struct {
	net.Conn
}

func (c *duplexConn) ReadFrom(r io.Reader) (int64, error) {
	return Copy(c.Conn, r)
}

func (c *duplexConn) WriteTo(w io.Writer) (int64, error) {
	return Copy(w, c.Conn)
}

func (c *duplexConn) CloseRead() error {
	if closer, ok := c.Conn.(CloseReader); ok {
		return closer.CloseRead()
	}
	return errors.New("not supported")
}

func (c *duplexConn) CloseWrite() error {
	if closer, ok := c.Conn.(CloseWriter); ok {
		return closer.CloseWrite()
	}
	return errors.New("not supported")
}

// Relay is ...
func Relay(c, rc net.Conn) error {
	l, ok := c.(DuplexConn)
	if !ok {
		l = &duplexConn{Conn: c}
	}

	r, ok := rc.(DuplexConn)
	if !ok {
		r = &duplexConn{Conn: rc}
	}

	return relay(l, r)
}

func relay(c, rc DuplexConn) error {
	errCh := make(chan error, 1)
	go func(c, rc DuplexConn, errCh chan error) {
		_, err := Copy(rc, c)
		if err != nil {
			rc.Close()
			c.Close()
		} else {
			rc.CloseWrite()
			c.CloseRead()
		}

		errCh <- err
	}(c, rc, errCh)

	_, err := Copy(c, rc)
	if err != nil {
		c.Close()
		rc.Close()
	} else {
		c.CloseWrite()
		rc.CloseRead()
	}

	return xerror.CombineError(err, <-errCh)
}

// Copy is ...
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

	const MaxBufferSize = 16 << 10
	sc, b := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

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
			if !errors.Is(er, io.EOF) {
				err = er
			}
			break
		}
	}
	return n, err
}
