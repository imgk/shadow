package shadowsocks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/protocol"
	"github.com/imgk/shadow/protocol/shadowsocks/core"
	tls "github.com/imgk/shadow/protocol/shadowsocks-tls/core"
)

func init() {
	protocol.RegisterHandler("ss-tls", func(s string, timeout time.Duration) (common.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("shadowsocks-tls", func(s string, timeout time.Duration) (common.Handler, error) {
		return NewHandler(s, timeout)
	})
}

type Handler struct {
	Dialer  *tls.Dialer
	Cipher  core.Cipher
	server  string
	timeout time.Duration
}

func NewHandler(url string, timeout time.Duration) (*Handler, error) {
	server, cipher, password, err := ParseUrl(url)
	if err != nil {
		return nil, err
	}

	if _, err := net.ResolveUDPAddr("udp", server); err != nil {
		return nil, err
	}

	ciph, err := core.NewCipher(cipher, password)
	if err != nil {
		return nil, err
	}

	dialer, err := tls.NewDialer(server, password)
	if err != nil {
		return nil, err
	}

	return &Handler{
		Dialer:  dialer,
		Cipher:  ciph,
		server:  server,
		timeout: timeout,
	}, nil
}

func (*Handler) Close() error {
	return nil
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) (err error) {
	defer conn.Close()

	addr, ok := tgt.(common.Addr)
	if !ok {
		addr, err = common.ResolveAddrBuffer(tgt, make([]byte, common.MaxAddrLen))
		if err != nil {
			return fmt.Errorf("resolve addr error: %v", err)
		}
	}

	rc, err := h.Dialer.Dial("tcp", h.server)
	if err != nil {
		return fmt.Errorf("dial server %v error: %v", h.server, err)
	}
	rc = core.NewConn(rc, h.Cipher)
	defer rc.Close()

	if _, err := rc.Write(addr); err != nil {
		return fmt.Errorf("write to server %v error: %v", h.server, err)
	}

	if err := common.Relay(conn, rc); err != nil {
		if ne := net.Error(nil); errors.As(err, &ne) {
			if ne.Timeout() {
				return nil
			}
		}
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
			return nil
		}

		return fmt.Errorf("relay error: %v", err)
	}

	return nil
}

func (h *Handler) HandlePacket(conn common.PacketConn) error {
	defer conn.Close()

	raddr, err := net.ResolveUDPAddr("udp", h.server)
	if err != nil {
		return fmt.Errorf("parse udp address %v error: %v", h.server, err)
	}

	rc, err := h.Dialer.ListenPacket("udp", ":")
	if err != nil {
		conn.Close()
		return err
	}
	rc = core.NewPacketConn(rc, h.Cipher)

	errCh := make(chan error, 1)
	go copyWithChannel(conn, rc, h.timeout, raddr, errCh)

	slice := common.Get()
	defer common.Put(slice)
	b := slice.Get()

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

		raddr, er := common.ParseAddr(b[:n])
		if er != nil {
			err = fmt.Errorf("parse addr error: %v", er)
			break
		}

		_, er = conn.WriteFrom(b[len(raddr):n], raddr)
		if er != nil {
			err = fmt.Errorf("write packet error: %v", er)
			break
		}
	}

	conn.Close()
	rc.Close()

	if err != nil {
		<-errCh
		return err
	}

	return <-errCh
}

func copyWithChannel(conn common.PacketConn, rc net.PacketConn, timeout time.Duration, raddr net.Addr, errCh chan error) {
	slice := common.Get()
	defer common.Put(slice)
	b := slice.Get()

	buf := [common.MaxAddrLen]byte{}
	for {
		n, tgt, err := conn.ReadTo(b[common.MaxAddrLen:])
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
				errCh <- fmt.Errorf("resolve addr error: %w", err)
				break
			}
		}

		copy(b[common.MaxAddrLen-len(addr):], addr)

		rc.SetWriteDeadline(time.Now().Add(timeout))
		_, err = rc.WriteTo(b[common.MaxAddrLen-len(addr):common.MaxAddrLen+n], raddr)
		if err != nil {
			errCh <- err
			break
		}
	}
}
