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
	// Auth is ...
	Auth *proxy.Auth

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

	c, rc, err := func() (c net.Conn, rc *net.UDPConn, err error) {
		rc, err = net.ListenUDP("udp", nil)
		if err != nil {
			return
		}
		defer func(c *net.UDPConn) {
			if err != nil {
				c.Close()
			}
		}(rc)

		addr := rc.LocalAddr().(*net.UDPAddr)
		c, sAddr, err := h.Dial(addr, socks.CmdAssociate)
		if err != nil {
			return
		}
		defer func(c net.Conn) {
			if err != nil {
				c.Close()
			}
		}(c)

		raddr, err := socks.ResolveUDPAddr(sAddr)
		if err != nil {
			return
		}

		rc.Close()
		rc, err = net.DialUDP("udp", addr, raddr)
		if err != nil {
			return
		}

		go func(conn net.Conn, rc *net.UDPConn) {
			b := make([]byte, 1)
			for {
				if _, err := conn.Read(b); err != nil {
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
			rc.SetReadDeadline(time.Now())
		}(c, rc)
		return
	}()
	if err != nil {
		return err
	}
	defer c.Close()
	defer rc.Close()

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
						bb := b[offset+3:]
						bb[0] = socks.AddrTypeIPv4
						copy(bb[1:], ipv4)
						bb[1+net.IPv4len] = byte(nAddr.Port >> 8)
						bb[1+net.IPv4len+1] = byte(nAddr.Port)
					} else {
						ipv6 := nAddr.IP.To16()
						offset = socks.MaxAddrLen - 1 - net.IPv6len - 2
						bb := b[offset+3:]
						bb[0] = socks.AddrTypeIPv6
						copy(bb[1:], ipv6)
						bb[1+net.IPv6len] = byte(nAddr.Port >> 8)
						bb[1+net.IPv6len+1] = byte(nAddr.Port)
					}
				} else {
					err = errors.New("addr type error")
					return
				}
				b[offset], b[offset+1], b[offset+2] = 0, 0, 0
				return
			}(tgt, b[:3+socks.MaxAddrLen])
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
