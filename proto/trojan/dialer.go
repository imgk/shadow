package trojan

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"

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

// MuxDialer is ...
type MuxDialer struct {
	// Dialer is ...
	Dialer Dialer
	// Ticker is ...
	Ticker *time.Ticker
	// Config is ...
	Config smux.Config
	// MaxConn is ...
	MaxConn int
	// EmptyAddr is ...
	EmptyAddr [1 + 1 + 4 + 2 + 2]byte

	mu     sync.Mutex
	conns  map[*smux.Session]struct{}
	closed chan struct{}
}

// Configure is ...
func (d *MuxDialer) Configure(dialer Dialer, ver int) *MuxDialer {
	if d, ok := dialer.(*MuxDialer); ok {
		return d
	}

	// smux version 1
	cmd := byte(0x7f)
	if ver == 2 {
		// smux version 2
		cmd = 0x8f
	}

	d.Dialer = dialer
	d.Ticker = time.NewTicker(time.Minute * 3)
	d.Config = smux.Config{
		Version:           ver,
		KeepAliveInterval: 10 * time.Second,
		KeepAliveTimeout:  30 * time.Second,
		MaxFrameSize:      32768,
		MaxReceiveBuffer:  4194304,
		MaxStreamBuffer:   65536,
	}
	if err := smux.VerifyConfig(&d.Config); err != nil {
		log.Panic(errors.New("smux config error"))
	}
	d.MaxConn = 8
	d.EmptyAddr = [...]byte{cmd, socks.AddrTypeIPv4, 0, 0, 0, 0, 0, 0, 0x0d, 0x0a}
	d.conns = make(map[*smux.Session]struct{})
	d.closed = make(chan struct{})

	go func(d *MuxDialer) {
		defer d.Ticker.Stop()
	LOOP:
		for {
			select {
			case <-d.Ticker.C:
			case <-d.closed:
				break LOOP
			}

			d.mu.Lock()
			for sess := range d.conns {
				if sess.IsClosed() {
					delete(d.conns, sess)
					continue
				}

				if sess.NumStreams() == 0 {
					sess.Close()
					delete(d.conns, sess)
				}
			}
			d.mu.Unlock()
		}
	}(d)
	return d
}

// Close is ...
func (d *MuxDialer) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

// Dial is ...
func (d *MuxDialer) Dial(cmd byte, addr net.Addr) (net.Conn, error) {
	d.mu.Lock()
	for sess := range d.conns {
		if sess.NumStreams() < d.MaxConn {
			if sess.IsClosed() {
				delete(d.conns, sess)
				continue
			}

			conn, err := sess.OpenStream()
			if err != nil {
				if errors.Is(err, smux.ErrGoAway) {
					continue
				}
				if sess.IsClosed() {
					delete(d.conns, sess)
					continue
				}
				if sess.NumStreams() == 0 {
					sess.Close()
					delete(d.conns, sess)
					continue
				}
			}

			d.mu.Unlock()
			return conn, err
		}
	}
	d.mu.Unlock()

	conn, err := d.Dialer.Dial(d.EmptyAddr[0], &socks.Addr{Addr: d.EmptyAddr[1:]})
	if err != nil {
		return nil, err
	}

	sess, err := smux.Client(conn, &d.Config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	stream, err := sess.OpenStream()
	if err != nil {
		sess.Close()
		return nil, err
	}

	if err := WriteAddr(stream, cmd, addr); err != nil {
		sess.Close()
		return nil, err
	}

	d.mu.Lock()
	d.conns[sess] = struct{}{}
	d.mu.Unlock()
	return stream, nil
}
