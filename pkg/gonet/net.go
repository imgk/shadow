package gonet

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/xerrors"
)

// Handler is ...
type Handler interface {
	// Closer is ...
	io.Closer
	// Handle is ...
	Handle(Conn, net.Addr) error
	// HandlePacket is ...
	HandlePacket(PacketConn) error
}

// PacketConn is ...
type PacketConn interface {
	// LocalAddr is ...
	LocalAddr() net.Addr
	// RemoteAddr is ...
	RemoteAddr() net.Addr
	// SetDeadline is ...
	SetDeadline(time.Time) error
	// SetReadDeadline is ...
	SetReadDeadline(time.Time) error
	// SetWriteDeadline is ...
	SetWriteDeadline(time.Time) error
	// ReadTo is ...
	ReadTo([]byte) (int, net.Addr, error)
	// WriteFrom is ...
	WriteFrom([]byte, net.Addr) (int, error)
	// Close is ...
	Close() error
}

// CloseReader is ...
type CloseReader interface {
	// CloseRead is ...
	CloseRead() error
}

// CloseWriter is ...
type CloseWriter interface {
	// CloseWrite is ...
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

// conn is ...
type conn struct {
	net.Conn
}

// CloseRead is ...
func (c *conn) CloseRead() error {
	if closer, ok := c.Conn.(CloseReader); ok {
		return closer.CloseRead()
	}
	return errors.New("not supported")
}

// CloseWrite is ...
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
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			errCh <- nil
			return
		}
		rc.SetReadDeadline(time.Now())
		errCh <- err
	}(c, rc, errCh)

	_, err := Copy(c, rc)
	if closer, ok := c.(CloseWriter); ok {
		closer.CloseWrite()
	}
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		err = <-errCh
		return err
	}
	c.SetReadDeadline(time.Now())

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
