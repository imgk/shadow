package gonet

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/xerrors"
)

// Handler is ...
type Handler interface {
	io.Closer
	Handle(Conn, net.Addr) error
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

// CloseWriter is ...
type CloseWriter interface {
	CloseWrite() error
}

// Conn is ...
type Conn interface {
	net.Conn
	CloseReader
	CloseWriter
}

// NewConn is ...
func NewConn(nc net.Conn) Conn {
	if c, ok := nc.(Conn); ok {
		return c
	}
	return &conn{Conn: nc}
}

type conn struct {
	net.Conn
}

func (c *conn) ReadFrom(r io.Reader) (int64, error) {
	return Copy(c.Conn, r)
}

func (c *conn) WriteTo(w io.Writer) (int64, error) {
	return Copy(w, c.Conn)
}

func (c *conn) CloseRead() error {
	if closer, ok := c.Conn.(CloseReader); ok {
		return closer.CloseRead()
	}
	return errors.New("not supported")
}

func (c *conn) CloseWrite() error {
	if closer, ok := c.Conn.(CloseWriter); ok {
		return closer.CloseWrite()
	}
	return errors.New("not supported")
}

// Relay is ...
func Relay(c, rc net.Conn) error {
	errCh := make(chan error, 1)
	go func(c, rc net.Conn, errCh chan error) {
		_, err := Copy(rc, c)
		if closer, ok := rc.(CloseWriter); ok {
			closer.CloseWrite()
		}
		if err != nil {
			rc.SetReadDeadline(time.Now())
		}
		errCh <- err
	}(c, rc, errCh)

	_, err := Copy(c, rc)
	if closer, ok := c.(CloseWriter); ok {
		closer.CloseWrite()
	}
	if err != nil {
		c.SetReadDeadline(time.Now())
	}

	return xerrors.CombineError(err, <-errCh)
}

// Copy is ...
func Copy(w io.Writer, r io.Reader) (n int64, err error) {
	if c, ok := r.(*conn); ok {
		r = c.Conn
	}
	if c, ok := w.(*conn); ok {
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
