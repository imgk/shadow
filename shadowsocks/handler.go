package shadowsocks

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/imgk/shadowsocks-windivert/utils"
)

type Handler struct {
	Cipher
	*net.UDPAddr
	addr    string
	timeout time.Duration
}

func NewHandler(url string, timeout time.Duration) (*Handler, error) {
	server, cipher, password, err := ParseUrl(url)
	if err != nil {
		return nil, err
	}

	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}

	ciph, err := NewCipher(cipher, password)
	if err != nil {
		return nil, err
	}

	return &Handler{
		Cipher:  ciph,
		UDPAddr: raddr,
		addr:    server,
		timeout: timeout,
	}, nil
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	addr, err := utils.ResolveAddr(tgt)
	if err != nil {
		return fmt.Errorf("resolve addr error: %v", err)
	}

	rc, err := net.Dial("tcp", h.addr)
	if err != nil {
		return fmt.Errorf("dial server %v error: %v", h.addr, err)
	}
	rc.(*net.TCPConn).SetKeepAlive(true)
	rc = NewConn(rc, h.Cipher)

	if _, err := rc.Write(addr); err != nil {
		return fmt.Errorf("write to server %v error: %v", h.addr, err)
	}

	if err := relay(conn.(DuplexConn), rc.(DuplexConn)); err != nil {
		if ne, ok := err.(net.Error); ok {
			if ne.Timeout() {
				return nil
			}
		} else {
			if err == io.ErrClosedPipe || err == io.EOF {
				return nil
			}

		}
		return fmt.Errorf("relay error: %v", err)
	}

	return nil
}

type DuplexConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

func relay(c, rc DuplexConn) error {
	defer c.Close()
	defer rc.Close()

	errCh := make(chan error, 1)

	go func() {
		_, err := io.Copy(c, rc)
		if err != nil {
			c.Close()
			rc.Close()
		} else {
			c.CloseWrite()
			rc.CloseRead()
		}

		errCh <- err
	}()

	_, err := io.Copy(rc, c)
	if err != nil {
		rc.Close()
		c.Close()
	} else {
		rc.CloseWrite()
		c.CloseRead()
	}

	if err != nil {
		<-errCh
		return err
	}

	return <-errCh
}

func (h *Handler) HandlePacket(conn utils.PacketConn) error {
	rc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	rc = NewPacketConn(rc, h.Cipher)

	errCh := make(chan error, 1)

	go func() {
		b := make([]byte, 65536)

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

			addr, err := utils.ResolveAddr(tgt)
			if err != nil {
				errCh <- fmt.Errorf("resolve addr error: %v", err)
				break
			}

			copy(b[utils.MaxAddrLen-len(addr):], addr)

			rc.SetDeadline(time.Now().Add(h.timeout))
			_, err = rc.WriteTo(b[utils.MaxAddrLen-len(addr):utils.MaxAddrLen+n], h.UDPAddr)
			if err != nil {
				errCh <- err
				break
			}
		}
	}()

	b := make([]byte, 65536)

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
