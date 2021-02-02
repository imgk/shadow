package shadowsocks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/protocol"
	"github.com/imgk/shadow/protocol/shadowsocks/core"

	// other protocols
	"github.com/imgk/shadow/protocol/shadowsocks/http2"
	"github.com/imgk/shadow/protocol/shadowsocks/online"
)

func init() {
	protocol.RegisterHandler("ss", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("shadowsocks", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("ss-tls", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("shadowsocks-tls", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("ss-h2", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return http2.NewHandler(s, timeout)
	})
	protocol.RegisterHandler("shadowsocks-h2", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return http2.NewHandler(s, timeout)
	})
	protocol.RegisterHandler("ss-h3", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return http2.NewQUICHandler(s, timeout)
	})
	protocol.RegisterHandler("shadowsocks-h3", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return http2.NewQUICHandler(s, timeout)
	})
	protocol.RegisterHandler("ss-online", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return online.NewHandler(s, timeout)
	})
	protocol.RegisterHandler("shadowsocks-online", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return online.NewHandler(s, timeout)
	})
	protocol.RegisterHandler("online", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return online.NewHandler(s, timeout)
	})
}

// Dialer is ...
type Dialer interface {
	Dial(string, string) (net.Conn, error)
	ListenPacket(string, string) (net.PacketConn, error)
}

// NetDialer is ...
type NetDialer struct {
	Dialer net.Dialer
}

// NewNetDialer is ...
func NewNetDialer(server, password string) *NetDialer {
	return &NetDialer{}
}

// Dial is ...
func (d *NetDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, nil
}

// ListenPacket is ...
func (d *NetDialer) ListenPacket(network, addr string) (net.PacketConn, error) {
	return net.ListenPacket(network, addr)
}

// Handler is ...
type Handler struct {
	// Dialer is ...
	Dialer Dialer
	// Cipehr is ...
	Cipher *core.Cipher

	server  string
	timeout time.Duration
}

// NewHandler is ...
func NewHandler(s string, timeout time.Duration) (handler *Handler, err error) {
	server, method, password, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	if _, err := net.ResolveUDPAddr("udp", server); err != nil {
		return nil, err
	}

	cipher, err := core.NewCipher(method, password)
	if err != nil {
		return nil, err
	}

	dialer := Dialer(nil)
	if strings.HasPrefix(s, "ss-tls") || strings.HasPrefix(s, "shadowsocks-tls") {
		dialer, err = NewTLSDialer(server, password)
	} else {
		dialer = NewNetDialer(server, password)
	}
	if err != nil {
		return
	}

	handler = &Handler{
		Dialer:  dialer,
		Cipher:  cipher,
		server:  server,
		timeout: timeout,
	}
	return
}

// Close is ...
func (*Handler) Close() error {
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn net.Conn, tgt net.Addr) (err error) {
	defer conn.Close()

	addr, ok := tgt.(*socks.Addr)
	if !ok {
		addr, err = socks.ResolveAddrBuffer(tgt, make([]byte, socks.MaxAddrLen))
		if err != nil {
			return fmt.Errorf("resolve addr error: %w", err)
		}
	}

	rc, err := h.Dialer.Dial("tcp", h.server)
	if err != nil {
		return fmt.Errorf("dial server %v error: %w", h.server, err)
	}
	rc = core.NewConn(rc, h.Cipher)
	defer rc.Close()

	if _, err := rc.Write(addr.Addr); err != nil {
		return fmt.Errorf("write to server %v error: %w", h.server, err)
	}

	if err := gonet.Relay(conn, rc); err != nil {
		if ne := net.Error(nil); errors.As(err, &ne) {
			if ne.Timeout() {
				return nil
			}
		}
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
			return nil
		}

		return fmt.Errorf("relay error: %w", err)
	}

	return nil
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	defer conn.Close()

	raddr, err := net.ResolveUDPAddr("udp", h.server)
	if err != nil {
		return fmt.Errorf("parse udp address %v error: %w", h.server, err)
	}

	rc, err := h.Dialer.ListenPacket("udp", ":")
	if err != nil {
		conn.Close()
		return err
	}
	rc = core.NewPacketConn(rc, h.Cipher)

	const MaxBufferSize = 16 << 10

	errCh := make(chan error, 1)
	go func(conn gonet.PacketConn, rc net.PacketConn, timeout time.Duration, raddr net.Addr, errCh chan error) (err error) {
		sc, b := pool.Pool.Get(MaxBufferSize)
		defer func() {
			pool.Pool.Put(sc)
			errCh <- err
		}()

		for {
			nr, tgt, er := conn.ReadTo(b[socks.MaxAddrLen:])
			if err != nil {
				if errors.Is(er, io.EOF) || errors.Is(er, os.ErrDeadlineExceeded) {
					break
				}
				err = er
				break
			}

			offset, er := func(addr net.Addr, b []byte) (offset int, err error) {
				if addr, ok := addr.(*socks.Addr); ok {
					offset = socks.MaxAddrLen - len(addr.Addr)
					copy(b[offset:], addr.Addr)
					return
				}
				if nAddr, ok := addr.(*net.UDPAddr); ok {
					if ipv4 := nAddr.IP.To4(); ipv4 != nil {
						offset = socks.MaxAddrLen - 1 - net.IPv4len - 2
						b = b[offset:]
						b[0] = socks.AddrTypeIPv4
						copy(b[1:], ipv4)
						b[1+net.IPv4len] = byte(nAddr.Port >> 8)
						b[1+net.IPv4len+1] = byte(nAddr.Port)
					} else {
						ipv6 := nAddr.IP.To16()
						offset = socks.MaxAddrLen - 1 - net.IPv6len - 2
						b = b[offset:]
						b[0] = socks.AddrTypeIPv6
						copy(b[1:], ipv6)
						b[1+net.IPv6len] = byte(nAddr.Port >> 8)
						b[1+net.IPv6len+1] = byte(nAddr.Port)
					}
					return
				}
				err = errors.New("addr type error")
				return
			}(tgt, b[:socks.MaxAddrLen])
			if er != nil {
				err = er
				break
			}

			if _, ew := rc.WriteTo(b[offset:socks.MaxAddrLen+nr], raddr); ew != nil {
				err = ew
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(conn, rc, h.timeout, raddr, errCh)

	sc, b := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

	for {
		rc.SetReadDeadline(time.Now().Add(h.timeout))
		nr, _, er := rc.ReadFrom(b)
		if er != nil {
			if errors.Is(er, os.ErrDeadlineExceeded) {
				break
			}
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
			}
			err = fmt.Errorf("read packet error: %v", er)
			break
		}

		raddr, er := socks.ParseAddr(b[:nr])
		if er != nil {
			err = fmt.Errorf("parse addr error: %v", er)
			break
		}

		if _, ew := conn.WriteFrom(b[len(raddr.Addr):nr], raddr); ew != nil {
			err = fmt.Errorf("write packet error: %v", ew)
			break
		}
	}
	conn.SetReadDeadline(time.Now())

	if err == nil {
		err = <-errCh
	} else {
		<-errCh
	}

	return err
}
