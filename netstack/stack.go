package netstack

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/imgk/shadow/log"
)

const MaxUDPPacketSize = 4096 // Max 65536

type Stack interface {
	io.Reader
	io.WriterTo
	io.Writer
	io.ReaderFrom
	io.Closer
}

type CloseReader interface {
	CloseRead() error
}

type CloseWriter interface {
	CloseWrite() error
}

type DuplexConn interface {
	net.Conn
	CloseReader
	CloseWriter
}

type Conn struct {
	net.Conn
}

func (c Conn) CloseRead() error {
	if close, ok := c.Conn.(CloseReader); ok {
		return close.CloseRead()
	}

	return c.Conn.Close()
}

func (c Conn) CloseWrite() error {
	if close, ok := c.Conn.(CloseWriter); ok {
		return close.CloseWrite()
	}

	return c.Conn.Close()
}

func (s *stack) RedirectTCP(conn net.Conn, target *net.TCPAddr) {
	defer conn.Close()

	rc, err := net.DialTCP("tcp", nil, target)
	if err != nil {
		log.Logf("dial remote %v error: %v", target, err)
		return
	}
	defer rc.Close()

	if err := relay(conn.(core.TCPConn), rc); err != nil {
		if ne, ok := err.(net.Error); ok {
			if ne.Timeout() {
				return
			}
		}
		if err == io.ErrClosedPipe || err == io.EOF {
			return
		}

		log.Logf("relay error: %v", err)
	}
}

func Copy(w io.Writer, r io.Reader) (n int64, err error) {
	if wt, ok := r.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	if c, ok := r.(Conn); ok {
		if wt, ok := c.Conn.(io.WriterTo); ok {
			return wt.WriteTo(w)
		}
	}
	if rt, ok := w.(io.ReaderFrom); ok {
		return rt.ReadFrom(r)
	}
	if c, ok := w.(Conn); ok {
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

func Relay(c, rc net.Conn) error {
	l, ok := c.(core.TCPConn)
	if !ok {
		return fmt.Errorf("the front conn should be the income one")
	}

	r, ok := rc.(DuplexConn)
	if !ok {
		r = Conn{ Conn: rc }
	}

	return relay(l, r)
}

func relay(c core.TCPConn, rc DuplexConn) error {
	errCh := make(chan error, 1)
	go relay2(c, rc, errCh)

	_, err := Copy(c, rc)
	if err != nil {
		c.Close()
		rc.Close()
	} else {
		c.CloseWrite()
		rc.CloseRead()
	}

	if err != nil {
		<-errCh
		return err
	}

	return <-errCh
}

func relay2(c core.TCPConn, rc DuplexConn, errCh chan error) {
	_, err := Copy(rc, c)
	if err != nil {
		rc.Close()
		c.Close()
	} else {
		rc.CloseWrite()
		c.CloseRead()
	}

	errCh <- err
}

func (s *stack) HandleTCP(conn net.Conn, addr net.Addr) {
	if err := s.Handler.Handle(conn, addr); err != nil {
		log.Logf("handle tcp error: %v", err)
	}
}

func CloseTimeout(conn *UDPConn, timer *time.Timer, sigCh chan struct{}) {
	select {
	case <-sigCh:
		return
	case <-timer.C:
		conn.Close()
	}
}

func (s *stack) HandleMessage(conn *UDPConn) {
	b := make([]byte, 4096)
	m := new(dnsmessage.Message)

	timer := time.NewTimer(time.Second * 3)
	sigCh := make(chan struct{})

	go CloseTimeout(conn, timer, sigCh)

	for {
		timer.Reset(time.Second * 3)
		n, raddr, err := conn.ReadTo(b[2:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			log.Logf("receive dns from packet conn error: %v", err)
			continue
		}

		if err := m.Unpack(b[2 : 2+n]); err != nil {
			log.Logf("parse dns error: %v", err)
			continue
		}

		if m, err = s.ResolveDNS(m); err != nil {
			log.Logf("resolve dns error: %v", err)
			continue
		}

		if m.Header.Response {
			bb, err := m.AppendPack(b[:2])
			if err != nil {
				log.Logf("append pack dns message error: %v", err)
				continue
			}
			n = len(bb) - 2
		} else {
			nr, err := s.Resolver.Resolve(b, n)
			if err != nil {
				log.Logf("resolve dns error: %v", err)
				continue
			}
			n = nr
		}

		if _, err := conn.WriteFrom(b[2:2+n], raddr); err != nil {
			log.Logf("write back to packet conn error: %v", err)
		}
	}

	close(sigCh)

	s.Del(conn)
	conn.Close()
}

func (s *stack) RedirectUDP(conn DirectUDPConn) {
	b := make([]byte, MaxUDPPacketSize)
	for {
		conn.PacketConn.SetDeadline(time.Now().Add(time.Minute))
		n, raddr, er := conn.PacketConn.ReadFrom(b)
		if er != nil {
			if ne, ok := er.(net.Error); ok {
				if ne.Timeout() {
					break
				}
			}

			log.Logf("read packet error: %v", er)
			break
		}

		_, er = conn.UDPConn.WriteFrom(b[:n], raddr.(*net.UDPAddr))
		if er != nil {
			log.Logf("write packet error: %v", er)
			break
		}
	}

	s.Del(conn)
	conn.Close()
	return
}

func (s *stack) HandleUDP(conn *UDPConn) {
	err := s.Handler.HandlePacket(conn)
	s.Del(conn)

	if err != nil {
		log.Logf("handle udp error: %v", err)
	}
}

func (s *stack) Add(conn PacketConn) {
	s.Lock()
	switch conn.(type) {
	case *UDPConn:
		s.conns[conn.(*UDPConn).UDPConn] = conn
	case DirectUDPConn:
		s.conns[conn.(DirectUDPConn).UDPConn] = conn
	}
	s.Unlock()
}

func (s *stack) Del(conn PacketConn) {
	s.Lock()
	switch conn.(type) {
	case *UDPConn:
		delete(s.conns, conn.(*UDPConn).UDPConn)
	case DirectUDPConn:
		delete(s.conns, conn.(DirectUDPConn).UDPConn)
	}
	s.Unlock()
}

func (s *stack) ReceiveTo(conn core.UDPConn, data []byte, target *net.UDPAddr) error {
	s.RLock()
	pc, ok := s.conns[conn]
	s.RUnlock()

	if !ok {
		log.Logf("connection from %v to %v does not exist", conn.LocalAddr(), target)
		return nil
	}

	return pc.WriteTo(data, target)
}

func (s *stack) Read(b []byte) (int, error) {
	return 0, errors.New("not supported")
}

func (s *stack) WriteTo(w io.Writer) (int64, error) {
	return 0, errors.New("not supported")
}

func (s *stack) Write(b []byte) (int, error) {
	return s.LWIPStack.Write(b)
}

func (s *stack) ReadFrom(r io.Reader) (int64, error) {
	b := make([]byte, 1500)

	for {
		n, err := r.Read(b)
		if err != nil {
			return 0, err
		}

		_, err = s.LWIPStack.Write(b[:n])
		if err != nil {
			return 0, err
		}
	}
}

func (s *stack) Close() error {
	s.Lock()
	for _, pc := range s.conns {
		pc.Close()
	}
	s.Unlock()

	return s.LWIPStack.Close()
}
