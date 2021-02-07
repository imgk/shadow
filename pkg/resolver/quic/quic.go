package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
)

var (
	_ net.Conn       = (*Conn)(nil)
	_ net.PacketConn = (*Conn)(nil)
)

// Resolver is ...
type Resolver struct {
	// Addr is ...
	Addr string
	// Config is ...
	Config tls.Config
	// Timeout is ...
	Timeout time.Duration

	sess quic.Session
}

// NewResolver is ...
func NewResolver(addr, domain string) (*Resolver, error) {
	resolver := &Resolver{
		Addr: addr,
		Config: tls.Config{
			ServerName:         domain,
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
			NextProtos:         []string{"dq"},
		},
		Timeout: time.Second * 3,
	}
	sess, err := quic.DialAddr(addr, &resolver.Config, &quic.Config{KeepAlive: true})
	if err != nil {
		return nil, err
	}
	resolver.sess = sess
	return resolver, nil
}

// Resolve is ...
func (r *Resolver) Resolve(b []byte, n int) (int, error) {
	conn, err := r.DialContext(nil, "udp", r.Addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.Write(b[2 : 2+n]); err != nil {
		return 0, err
	}

	conn.SetReadDeadline(time.Now().Add(r.Timeout))
	return conn.Read(b[2:])
}

// DialContext is ...
func (r *Resolver) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	stream, err := r.sess.OpenStream()
	if err == nil {
		return &Conn{Session: r.sess, Stream: stream}, nil
	}

	// TODO: how to close session
	r.sess.CloseWithError(0, "")
	// dial a new session when error happens
	r.sess, err = quic.DialAddr(r.Addr, &r.Config, &quic.Config{KeepAlive: true})
	if err != nil {
		return nil, err
	}
	stream, err = r.sess.OpenStream()
	return &Conn{Session: r.sess, Stream: stream}, nil
}

// Conn is ...
type Conn struct {
	quic.Session
	quic.Stream
}

// WriteTo is ...
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Write(b)
}

// Read is ...
func (c *Conn) Read(b []byte) (int, error) {
	n, err := Buffer(b).ReadFrom(c.Stream)
	return int(n), err
}

// ReadFrom is ...
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := Buffer(b).ReadFrom(c.Stream)
	return int(n), nil, err
}

// Buffer is ...
type Buffer []byte

// ReadFrom is ...
func (b Buffer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		nr, er := r.Read(b[n:])
		if nr > 0 {
			n += int64(nr)
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				break
			}
			err = er
			break
		}
		if int(n) == len(b) {
			err = io.ErrShortBuffer
			break
		}
	}
	return
}
