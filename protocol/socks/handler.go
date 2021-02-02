package socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/net/proxy"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/protocol"
)

func init() {
	protocol.RegisterHandler("socks", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("socks5", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return NewHandler(s, timeout)
	})
}

// Handler is ...
type Handler struct {
	Auth    *proxy.Auth
	server  string
	timeout time.Duration
}

// NewHandler is ...
func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	auth, server, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	if _, err := net.ResolveUDPAddr("udp", server); err != nil {
		return nil, err
	}

	handler := &Handler{
		Auth:    auth,
		server:  server,
		timeout: timeout,
	}
	return handler, nil
}

// Close is ...
func (*Handler) Close() error {
	return nil
}

// Dial is ...
func (h *Handler) Dial(tgt net.Addr, cmd byte) (net.Conn, *socks.Addr, error) {
	conn, err := net.Dial("tcp", h.server)
	if err != nil {
		return nil, nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}

	addr, err := socks.Handshake(conn, tgt, cmd, h.Auth)
	if err != nil {
		return nil, nil, err
	}

	return conn, addr, nil
}

// Handle is ...
func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, _, err := h.Dial(tgt, socks.CmdConnect)
	if err != nil {
		return err
	}
	defer rc.Close()

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

	c, rc, err := func(tgt net.Addr) (c net.Conn, rc *net.UDPConn, err error) {
		c, addr, err := h.Dial(tgt, socks.CmdAssociate)
		if err != nil {
			return
		}
		defer func() {
			if err != nil {
				c.Close()
			}
		}()

		raddr, err := socks.ResolveUDPAddr(addr)
		if err != nil {
			return
		}

		rc, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			return
		}

		go func(conn net.Conn, rc net.PacketConn) {
			b := [8]byte{}
			for {
				if _, err := conn.Read(b[:]); err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					if ne := net.Error(nil); errors.As(err, &ne) {
						if ne.Timeout() {
							continue
						}
					}
					break
				}
			}
			rc.Close()
			conn.Close()
		}(c, rc)
		return
	}(conn.LocalAddr())
	if err != nil {
		return err
	}

	const MaxBufferSize = 16 << 10

	// from local to remote
	errCh := make(chan error, 1)
	go func(conn gonet.PacketConn, rc *net.UDPConn, timeout time.Duration, errCh chan error) (err error) {
		sc, b := pool.Pool.Get(MaxBufferSize)
		defer func() {
			pool.Pool.Put(sc)
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				err = nil
			}
			errCh <- err
		}()

		for {
			n, tgt, er := conn.ReadTo(b[3+socks.MaxAddrLen:])
			if er != nil {
				err = er
				break
			}

			// parse remote address
			offset, er := func(tgt net.Addr, b []byte) (offset int, err error) {
				if addr, ok := tgt.(*socks.Addr); ok {
					offset = socks.MaxAddrLen - len(addr.Addr)
					copy(b[offset+3:], addr.Addr)
				}
				if nAddr, ok := tgt.(*net.UDPAddr); ok {
					if ipv4 := nAddr.IP.To4(); ipv4 != nil {
						offset = socks.MaxAddrLen - 1 - net.IPv4len - 2
						b = b[offset+3:]
						b[0] = socks.AddrTypeIPv4
						copy(b[1:], ipv4)
						b[1+net.IPv4len] = byte(nAddr.Port >> 8)
						b[1+net.IPv4len+1] = byte(nAddr.Port)
					} else {
						ipv6 := nAddr.IP.To16()
						offset = socks.MaxAddrLen - 1 - net.IPv6len - 2
						b = b[offset+3:]
						b[0] = socks.AddrTypeIPv6
						copy(b[1:], ipv6)
						b[1+net.IPv6len] = byte(nAddr.Port >> 8)
						b[1+net.IPv6len+1] = byte(nAddr.Port)
					}
				} else {
					err = errors.New("addr type error")
					return
				}
				b[offset], b[offset+1], b[offset+2] = 0, 0, 0
				return
			}(tgt, b)
			if er != nil {
				err = er
				break
			}

			if _, ew := rc.Write(b[offset : 3+socks.MaxAddrLen+n]); ew != nil {
				err = ew
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(conn, rc, h.timeout, errCh)

	// from remote to local
	sc, b := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

	for {
		rc.SetReadDeadline(time.Now().Add(h.timeout))
		n, er := rc.Read(b)
		if er != nil {
			err = er
			break
		}

		raddr, er := socks.ParseAddr(b[3:n])
		if er != nil {
			err = er
			break
		}

		if _, ew := conn.WriteFrom(b[3+len(raddr.Addr):n], raddr); ew != nil {
			err = ew
			break
		}
	}
	c.SetReadDeadline(time.Now())
	conn.SetReadDeadline(time.Now())

	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
		err = <-errCh
	} else {
		<-errCh
	}
	return err
}
