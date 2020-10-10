package socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/protocol"
)

func init() {
	protocol.RegisterHandler("socks", func(s string, timeout time.Duration) (common.Handler, error) {
		return NewHandler(s, timeout)
	})
}

type Handler struct {
	*Auth
	server  string
	timeout time.Duration
}

func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	auth, server, err := ParseUrl(s)
	if err != nil {
		return nil, err
	}

	if _, err := net.ResolveUDPAddr("udp", server); err != nil {
		return nil, err
	}

	return &Handler{
		Auth:    auth,
		server:  server,
		timeout: timeout,
	}, nil
}

func (*Handler) Close() error {
	return nil
}

func (h *Handler) Dial(tgt net.Addr, cmd byte) (net.Conn, common.Addr, error) {
	conn, err := net.Dial("tcp", h.server)
	if err != nil {
		return nil, nil, err
	}
	conn.(*net.TCPConn).SetKeepAlive(true)

	addr, err := Handshake(conn, tgt, cmd, h.Auth)
	if err != nil {
		return nil, nil, err
	}

	return conn, addr, nil
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, _, err := h.Dial(tgt, Connect)
	if err != nil {
		return err
	}
	defer rc.Close()

	if err := common.Relay(conn, rc); err != nil {
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

func closeFromRemote(conn net.Conn, rc net.PacketConn) {
	b := [8]byte{}

	for {
		if _, err := conn.Read(b[:]); err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					continue
				}
			}

			break
		}
	}

	rc.Close()	
}

func (h *Handler) HandlePacket(conn common.PacketConn) error {
	defer conn.Close()

	c, addr, err := h.Dial(conn.LocalAddr(), Associate)
	if err != nil {
		return err
	}
	defer c.Close()

	raddr, err := common.ResolveUDPAddr(addr)
	if err != nil {
		return err
	}

	rc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	defer rc.Close()

	go closeFromRemote(c, rc)

	errCh := make(chan error, 1)
	go copyWithChannel(conn, rc, h.timeout, raddr, errCh)

	b := common.Get()
	defer common.Put(b)

	for {
		rc.SetReadDeadline(time.Now().Add(h.timeout))
		n, _, er := rc.ReadFrom(b)
		if er != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
			}
			err = fmt.Errorf("read packet error: %v", er)
			break
		}

		raddr, er := common.ParseAddr(b[3:n])
		if er != nil {
			err = fmt.Errorf("parse addr error: %v", er)
			break
		}

		_, er = conn.WriteFrom(b[3+len(raddr):n], raddr)
		if er != nil {
			err = fmt.Errorf("write packet error: %v", er)
			break
		}
	}

	conn.Close()
	rc.Close()
	c.Close()

	if err != nil {
		<-errCh
		return err
	}

	return <-errCh
}

func copyWithChannel(conn common.PacketConn, rc net.PacketConn, timeout time.Duration, raddr net.Addr, errCh chan error) {
	b := common.Get()
	defer common.Put(b)

	buf := [common.MaxAddrLen]byte{}
	for {
		n, tgt, err := conn.ReadTo(b[3+common.MaxAddrLen:])
		if err != nil {
			if err == io.EOF {
				errCh <- nil
				break
			}
			errCh <- err
			break
		}

		addr, ok := tgt.(common.Addr)
		if !ok {
			addr, err = common.ResolveAddrBuffer(tgt, buf[:])
			if err != nil {
				errCh <- fmt.Errorf("resolve addr error: %v", err)
				break
			}
		}

		offset := common.MaxAddrLen - len(addr)
		copy(b[3+offset:], addr)

		b[offset], b[offset+1], b[offset+2] = 0, 0, 0

		rc.SetWriteDeadline(time.Now().Add(timeout))
		_, err = rc.WriteTo(b[offset:3+common.MaxAddrLen+n], raddr)
		if err != nil {
			errCh <- err
			break
		}
	}
}
