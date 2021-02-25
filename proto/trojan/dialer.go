package trojan

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/gorilla/websocket"

	"github.com/imgk/shadow/pkg/socks"
)

// WriteHeaderAddr is ...
func WriteHeaderAddr(conn net.Conn, header []byte, cmd byte, tgt net.Addr) error {
	buff := make([]byte, HeaderLen+2+1+socks.MaxAddrLen+2)
	copy(buff, header)
	buff[HeaderLen+2] = cmd

	addr, ok := tgt.(*socks.Addr)
	if ok {
		buff = append(buff[:HeaderLen+2+1], addr.Addr...)
		buff = append(buff, 0x0d, 0x0a)
	} else {
		addr, err := socks.ResolveAddrBuffer(tgt, buff[HeaderLen+2+1:])
		if err != nil {
			return err
		}
		buff = append(buff[:HeaderLen+2+1+len(addr.Addr)], 0x0d, 0x0a)
	}

	_, err := conn.Write(buff)
	return err
}

// WriteAddr is ...
func WriteAddr(conn net.Conn, cmd byte, tgt net.Addr) error {
	buff := make([]byte, 1+socks.MaxAddrLen)
	buff[0] = cmd

	if addr, ok := tgt.(*socks.Addr); ok {
		buff = append(buff[:1], addr.Addr...)
	} else {
		addr, err := socks.ResolveAddrBuffer(tgt, buff[1:])
		if err != nil {
			return err
		}
		buff = buff[:1+len(addr.Addr)]
	}

	_, err := conn.Write(buff)
	return err
}

// NetDialer is ...
type NetDialer struct {
	// Dialer is ...
	Dialer net.Dialer
	// Addr is ...
	Addr string
}

// Dial is ...
func (d *NetDialer) Dial(network, addr string) (net.Conn, error) {
	return d.Dialer.Dial(network, d.Addr)
}

// DialContext is ...
func (d *NetDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, d.Addr)
}

// Dialer is ...
type Dialer interface {
	Dial(byte, net.Addr) (net.Conn, error)
}

// TLSDialer is ...
type TLSDialer struct {
	// Addr is ...
	Addr string
	// Config is ...
	Config tls.Config
	// Header is ...
	Header [HeaderLen + 2]byte
}

// Dial is ...
func (d *TLSDialer) Dial(cmd byte, addr net.Addr) (net.Conn, error) {
	conn, err := net.Dial("tcp", d.Addr)
	if err != nil {
		return nil, err
	}
	conn = tls.Client(conn, &d.Config)
	if err := WriteHeaderAddr(conn, d.Header[:], cmd, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// WebSocketDialer is ...
type WebSocketDialer struct {
	// Addr is ...
	Addr string
	// NetDialer is ...
	NetDialer NetDialer
	// Dialer is ...
	Dialer websocket.Dialer
	// Header is ...
	Header [HeaderLen + 2]byte
}

// Dial is ...
func (d *WebSocketDialer) Dial(cmd byte, addr net.Addr) (net.Conn, error) {
	wc, _, err := d.Dialer.Dial(d.Addr, nil)
	if err != nil {
		return nil, err
	}
	conn := &wsConn{Conn: wc, Reader: &emptyReader{}}
	if err := WriteHeaderAddr(conn, d.Header[:], cmd, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
