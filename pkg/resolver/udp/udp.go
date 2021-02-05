package udp

import (
	"context"
	"net"
	"time"
)

// Resolver is ...
type Resolver struct {
	// Dialer is ...
	Dialer net.Dialer
	// Addr is ...
	Addr string
	// Timeout is ...
	Timeout time.Duration
}

// Resolve is ...
func (r *Resolver) Resolve(b []byte, n int) (int, error) {
	conn, err := net.Dial("udp", r.Addr)
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
func (r *Resolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return r.Dialer.DialContext(ctx, "udp", r.Addr)
}
