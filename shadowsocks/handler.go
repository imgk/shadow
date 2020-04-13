package shadowsocks

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/imgk/shadowsocks-windivert/utils"
)

var buffer = sync.Pool{New: func() interface{} { return make([]byte, 65536) }}

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

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	addr, err := utils.ResolveAddr(tgt)
	if err != nil {
		return fmt.Errorf("resolve addr error: %v", err)
	}

	rc, err := net.Dial("tcp", h.server)
	if err != nil {
		return fmt.Errorf("dial server %v error: %v", h.server, err)
	}
	rc.(*net.TCPConn).SetKeepAlive(true)
	rc = NewConn(rc, h.Cipher)

	if _, err := rc.Write(addr); err != nil {
		return fmt.Errorf("write to server %v error: %v", h.server, err)
	}

	l, ok := conn.(DuplexConn)
	if !ok {
		l = NewDuplexConn(conn)
	}

	r, ok := rc.(DuplexConn)
	if !ok {
		r = NewDuplexConn(rc)
	}

	if err := relay(l, r); err != nil {
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

type duplexConn struct {
	net.Conn
}

func NewDuplexConn(conn net.Conn) *duplexConn {
	return &duplexConn{Conn: conn}
}

func (conn *duplexConn) CloseRead() error {
	return conn.SetReadDeadline(time.Now())
}

func (conn *duplexConn) CloseWrite() error {
	return conn.SetWriteDeadline(time.Now())
}

func relay(c, rc DuplexConn) error {
	defer c.Close()
	defer rc.Close()

	errCh := make(chan error, 1)
	go copyWaitError(c, rc, errCh)

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

func copyWaitError(c, rc DuplexConn, errCh chan error) {
	_, err := io.Copy(c, rc)
	if err != nil {
		c.Close()
		rc.Close()
	} else {
		c.CloseWrite()
		rc.CloseRead()
	}

	errCh <- err
}

func (h *Handler) HandlePacket(conn utils.PacketConn) error {
	raddr, err := net.ResolveUDPAddr("udp", h.server)
	if err != nil {
		conn.Close()
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

	b := buffer.Get().([]byte)
	defer buffer.Put(b)

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

func copyWithChannel(conn utils.PacketConn, rc net.PacketConn, timeout time.Duration, raddr net.Addr, errCh chan error) {
	b := buffer.Get().([]byte)
	defer buffer.Put(b)

	for {
		n, tgt, err := conn.ReadTo(b[utils.MaxAddrLen:])
		if err != nil {
			if err == io.EOF {
				errCh <- nil
				return
			}
			errCh <- err
			return
		}

		addr, err := utils.ResolveAddr(tgt)
		if err != nil {
			errCh <- fmt.Errorf("resolve addr error: %v", err)
			return
		}

		copy(b[utils.MaxAddrLen-len(addr):], addr)

		rc.SetDeadline(time.Now().Add(timeout))
		_, err = rc.WriteTo(b[utils.MaxAddrLen-len(addr):utils.MaxAddrLen+n], raddr)
		if err != nil {
			errCh <- err
			return
		}
	}
}
