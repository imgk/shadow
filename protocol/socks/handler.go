package socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/utils"
)

const (
	MaxUDPPacketSize = 4096 // Max 65536
)

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

func (h *Handler) Dial(tgt net.Addr, cmd byte) (net.Conn, utils.Addr, error) {
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
		}
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
			return nil
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

func NewDuplexConn(conn net.Conn) duplexConn {
	return duplexConn{Conn: conn}
}

func (conn duplexConn) CloseRead() error {
	return conn.SetReadDeadline(time.Now())
}

func (conn duplexConn) CloseWrite() error {
	return conn.SetWriteDeadline(time.Now())
}

func Copy(w io.Writer, r io.Reader) (n int64, err error) {
	if wt, ok := r.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	if c, ok := r.(duplexConn); ok {
		if wt, ok := c.Conn.(io.WriterTo); ok {
			return wt.WriteTo(w)
		}
	}
	if rt, ok := w.(io.ReaderFrom); ok {
		return rt.ReadFrom(r)
	}
	if c, ok := w.(duplexConn); ok {
		if rt, ok := c.Conn.(io.ReaderFrom); ok {
			return rt.ReadFrom(r)
		}
	}

	b := make([]byte, 4096)
	for {
		nr, er := r.Read(b)
		if nr > 0 {
			nw, ew := w.Write(b[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return n, err
}

func relay(c, rc DuplexConn) error {
	errCh := make(chan error, 1)
	go copyWaitError(c, rc, errCh)

	_, err := Copy(rc, c)
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
	_, err := Copy(c, rc)
	if err != nil {
		c.Close()
		rc.Close()
	} else {
		c.CloseWrite()
		rc.CloseRead()
	}

	errCh <- err
}

func (h *Handler) HandlePacket(conn netstack.PacketConn) error {
	defer conn.Close()

	c, addr, err := h.Dial(conn.LocalAddr(), Associate)
	if err != nil {
		return err
	}
	defer c.Close()

	raddr, err := utils.ResolveUDPAddr(addr)
	if err != nil {
		return err
	}

	rc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go copyWithChannel(conn, rc, h.timeout, raddr, errCh)

	b := make([]byte, 3+utils.MaxAddrLen+MaxUDPPacketSize)
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

		raddr, er := utils.ParseAddr(b[3:n])
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

func copyWithChannel(conn netstack.PacketConn, rc net.PacketConn, timeout time.Duration, raddr net.Addr, errCh chan error) {
	b := make([]byte, 3+utils.MaxAddrLen+MaxUDPPacketSize)
	for {
		n, tgt, err := conn.ReadTo(b[3+utils.MaxAddrLen:])
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

		offset := utils.MaxAddrLen - len(addr)
		copy(b[3+offset:], addr)

		b[offset], b[offset+1], b[offset+2] = 0, 0, 0

		rc.SetDeadline(time.Now().Add(timeout))
		_, err = rc.WriteTo(b[offset:3+utils.MaxAddrLen+n], raddr)
		if err != nil {
			errCh <- err
			break
		}
	}

	return
}
