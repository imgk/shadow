package shadowsocks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/utils"
)

const MaxUDPPacketSize = 4096 // Max 65536

type Handler struct {
	Cipher
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

	ciph, err := NewCipher(cipher, password)
	if err != nil {
		return nil, err
	}

	return &Handler{
		Cipher:  ciph,
		server:  server,
		timeout: timeout,
	}, nil
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) (err error) {
	defer conn.Close()

	addr, ok := tgt.(utils.Addr)
	if !ok {
		addr, err = utils.ResolveAddrBuffer(tgt, make([]byte, utils.MaxAddrLen))
		if err != nil {
			return fmt.Errorf("resolve addr error: %v", err)
		}
	}

	rc, err := net.Dial("tcp", h.server)
	if err != nil {
		return fmt.Errorf("dial server %v error: %v", h.server, err)
	}
	rc.(*net.TCPConn).SetKeepAlive(true)
	rc = NewConn(rc, h.Cipher)
	defer rc.Close()

	if _, err := rc.Write(addr); err != nil {
		return fmt.Errorf("write to server %v error: %v", h.server, err)
	}

	if err := netstack.Relay(conn, rc); err != nil {
		if ne, ok := err.(net.Error); ok {
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

func (h *Handler) HandlePacket(conn netstack.PacketConn) error {
	defer conn.Close()

	raddr, err := net.ResolveUDPAddr("udp", h.server)
	if err != nil {
		return fmt.Errorf("parse udp address %v error: %v", h.server, err)
	}

	rc, err := net.ListenPacket("udp", "")
	if err != nil {
		conn.Close()
		return err
	}
	rc = NewPacketConn(rc, h.Cipher)

	errCh := make(chan error, 1)
	go copyWithChannel(conn, rc, h.timeout, raddr, errCh)

	b := make([]byte, 32+utils.MaxAddrLen+MaxUDPPacketSize)
	for {
		rc.SetDeadline(time.Now().Add(h.timeout))
		n, _, er := rc.ReadFrom(b)
		if er != nil {
			if ne, ok := er.(net.Error); ok {
				if ne.Timeout() {
					break
				}
			}
			err = fmt.Errorf("read packet error: %v", er)
			break
		}

		raddr, er := utils.ParseAddr(b[:n])
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

func copyWithChannel(conn netstack.PacketConn, rc net.PacketConn, timeout time.Duration, raddr net.Addr, errCh chan error) {
	b := make([]byte, 32+utils.MaxAddrLen+MaxUDPPacketSize)
	for {
		n, tgt, err := conn.ReadTo(b[utils.MaxAddrLen:])
		if err != nil {
			if err == io.EOF {
				errCh <- nil
				break
			}
			errCh <- err
			break
		}

		addr, ok := tgt.(utils.Addr)
		if !ok {
			addr, err = utils.ResolveAddrBuffer(tgt, make([]byte, utils.MaxAddrLen))
			if err != nil {
				errCh <- fmt.Errorf("resolve addr error: %v", err)
				break
			}
		}

		copy(b[utils.MaxAddrLen-len(addr):], addr)

		rc.SetDeadline(time.Now().Add(timeout))
		_, err = rc.WriteTo(b[utils.MaxAddrLen-len(addr):utils.MaxAddrLen+n], raddr)
		if err != nil {
			errCh <- err
			break
		}
	}

	return
}
