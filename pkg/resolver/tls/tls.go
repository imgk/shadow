package tls

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"
)

// Resolver is ...
type Resolver struct {
	// Dialer is ...
	Dialer net.Dialer
	// Addr is ...
	Addr string
	// Config is ...
	Config tls.Config
	// Timeout is ...
	Timeout time.Duration
}

// Resolve is ...
func (r *Resolver) Resolve(b []byte, n int) (int, error) {
	conn, err := net.Dial("tcp", r.Addr)
	if err != nil {
		return 0, err
	}
	conn = tls.Client(conn, &r.Config)
	defer conn.Close()

	b[0], b[1] = byte(n>>8), byte(n)
	if _, err := conn.Write(b[:2+n]); err != nil {
		return 0, err
	}

	conn.SetReadDeadline(time.Now().Add(r.Timeout))
	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return 0, err
	}

	l := int(b[0])<<8 | int(b[1])
	if l > len(b)-2 {
		return 0, io.ErrShortBuffer
	}

	return io.ReadFull(conn, b[2:2+l])
}

// DialContext is ...
func (r *Resolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := r.Dialer.DialContext(ctx, "tcp", r.Addr)
	conn = tls.Client(conn, &r.Config)
	return conn, err
}
