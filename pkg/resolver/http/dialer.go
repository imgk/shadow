package http

import (
	"context"
	"crypto/tls"
	"net"
)

// NetDialer is ...
type NetDialer struct {
	// Dialer is ...
	Dialer net.Dialer
	// Addr is ...
	Addr string
	// Config is ...
	Config tls.Config
}

// Dial is ...
func (d *NetDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, d.Addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

// DialContext is ...
func (d *NetDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, d.Addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

// DialTLS is ...
func (d *NetDialer) DialTLS(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, d.Addr)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return tls.Client(conn, &d.Config), err
}

// DialTLSContext is ...
func (d *NetDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, d.Addr)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return tls.Client(conn, &d.Config), nil
}
