package netstack

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/imgk/shadow/netstack/core"
	"github.com/imgk/shadow/utils"
)

// Max 65536
const MaxBufferSize = 4096

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

func (c Conn) ReadFrom(r io.Reader) (int64, error) {
	return Copy(c.Conn, r)
}

func (c Conn) WriteTo(w io.Writer) (int64, error) {
	return Copy(w, c.Conn)
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

func Relay(c, rc net.Conn) error {
	l, ok := c.(core.Conn)
	if !ok {
		return fmt.Errorf("relay error")
	}

	r, ok := rc.(DuplexConn)
	if !ok {
		r = Conn{Conn: rc}
	}

	return relay(l, r)
}

func relay(c core.Conn, rc DuplexConn) error {
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

func relay2(c core.Conn, rc DuplexConn, errCh chan error) {
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

func Copy(w io.Writer, r io.Reader) (n int64, err error) {
	if wt, ok := r.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	if rt, ok := w.(io.ReaderFrom); ok {
		return rt.ReadFrom(r)
	}

	b := make([]byte, MaxBufferSize)
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

type PacketConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	ReadTo([]byte) (int, net.Addr, error)
	WriteFrom([]byte, net.Addr) (int, error)
	Close() error
}

func NewPacketConn(conn core.PacketConn, target net.Addr, addr net.Addr, stack *Stack) PacketConn {
	if target == nil && addr == nil {
		return UDPConn{PacketConn: conn, Stack: stack}
	}

	return FakeConn{PacketConn: conn, target: target, addr: addr}
}

type FakeConn struct {
	core.PacketConn
	target net.Addr
	addr   net.Addr
}

func (conn FakeConn) ReadTo(b []byte) (int, net.Addr, error) {
	n, _, err := conn.PacketConn.ReadTo(b)
	return n, conn.addr, err
}

func (conn FakeConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return conn.PacketConn.WriteFrom(b, conn.target)
}

type UDPConn struct {
	core.PacketConn
	Stack *Stack
}

func (conn UDPConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = conn.PacketConn.ReadTo(b)
		if err != nil {
			break
		}

		addr, err = conn.Stack.LookupAddr(addr)
		if err == ErrNotFound {
			continue
		}
		err = nil
		break
	}
	return
}

func (conn UDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	if saddr, ok := addr.(utils.Addr); ok {
		target, err := utils.ResolveUDPAddr(saddr)
		if err != nil {
			return 0, fmt.Errorf("resolve udp addr error: %w", err)
		}
		return conn.PacketConn.WriteFrom(b, target)
	}

	return conn.PacketConn.WriteFrom(b, addr)
}

type Handler interface {
	Handle(net.Conn, net.Addr) error
	HandlePacket(PacketConn) error
}

type Stack struct {
	core.Stack
	DomainTree *utils.DomainTree
	Resolver   utils.Resolver
	Handler    Handler
	Pool       sync.Pool
	counter    uint16
}

func NewStack(handler Handler, dev core.Device, resolver utils.Resolver, verbose bool) *Stack {
	s := &Stack{
		DomainTree: utils.NewDomainTree("."),
		Resolver:   resolver,
		Handler:    handler,
		Pool:       sync.Pool{New: func() interface{} { return make([]byte, 1024*2) }},
		counter:    uint16(time.Now().Unix()),
	}
	s.Stack.Init(dev, s, verbose)
	return s
}

func (s *Stack) Handle(conn core.Conn, target *net.TCPAddr) {
	addr, err := s.LookupAddr(target)
	if err == ErrNotFake {
		s.Info(fmt.Sprintf("proxyd %v <-TCP-> %v", conn.RemoteAddr(), target))
		if err := s.Handler.Handle(conn, target); err != nil {
			s.Error(fmt.Sprintf("handle tcp error: %v", err))
		}
		return
	}
	if err == ErrNotFound {
		s.Error(fmt.Sprintf("handle tcp error: target %v %v", target, err))
		conn.Close()
		return
	}

	s.Info(fmt.Sprintf("proxyd %v <-TCP-> %v", conn.RemoteAddr(), addr))
	if err := s.Handler.Handle(conn, addr); err != nil {
		s.Error(fmt.Sprintf("handle tcp error: %v", err))
	}
	return
}

func (s *Stack) HandlePacket(conn core.PacketConn, target *net.UDPAddr) {
	if target == nil {
		s.Info(fmt.Sprintf("proxyd %v <-UDP-> 0.0.0.0:0", conn.RemoteAddr()))
		if err := s.Handler.HandlePacket(NewPacketConn(conn, nil, nil, s)); err != nil {
			s.Error(fmt.Sprintf("handle udp error: %v", err))
		}
		return
	}

	addr, err := s.LookupAddr(target)
	if target.Port == 53 && err == ErrNotFake {
		s.Info(fmt.Sprintf("hijack %v <-UDP-> %v", conn.RemoteAddr(), target))
		s.HandleQuery(conn)
		return
	}
	if err == ErrNotFound {
		s.Error(fmt.Sprintf("%v not found", target))
		return
	}
	if err == ErrNotFake {
		s.Info(fmt.Sprintf("proxyd %v <-UDP-> 0.0.0.0:0", conn.RemoteAddr()))
		if err := s.Handler.HandlePacket(NewPacketConn(conn, nil, nil, s)); err != nil {
			s.Error(fmt.Sprintf("handle udp error: %v", err))
		}
		return
	}

	s.Info(fmt.Sprintf("proxyd %v <-UDP-> %v", conn.RemoteAddr(), addr))
	if err := s.Handler.HandlePacket(NewPacketConn(conn, target, addr, s)); err != nil {
		s.Error(fmt.Sprintf("handle udp error: %v", err))
	}
	return
}

func (s *Stack) HandleQuery(conn core.PacketConn) {
	defer conn.Close()

	b := s.Pool.Get().([]byte)
	m := new(dns.Msg)
	defer s.Pool.Put(b)

	for {
		conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		n, addr, err := conn.ReadTo(b[2:])
		if err != nil {
			s.Pool.Put(b)

			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() {
					break
				}
			}
			s.Error(fmt.Sprintf("read dns error: %v", err))
			break
		}

		if err := m.Unpack(b[2:2+n]); err != nil {
			s.Error(fmt.Sprintf("unpack message error: %v", err))
			return
		}

		if len(m.Question) == 0 {
			s.Error("no question in message")
			return
		}
		s.Info(fmt.Sprintf("queryd %v ask for %v", conn.RemoteAddr(), m.Question[0].Name))

		s.HandleMessage(m)
		if m.MsgHdr.Response {
			bb, err := m.PackBuffer(b[2:])
			if err != nil {
				s.Error("append message error: " + err.Error())
				return
			}
			n = len(bb)
		} else {
			nr, err := s.Resolver.Resolve(b, n)
			if err != nil {
				if ne, ok := err.(net.Error); ok {
					if ne.Timeout() {
						return
					}
				}
				s.Error("resolve dns error: " + err.Error())
				return
			}
			n = nr
		}

		if _, err := conn.WriteFrom(b[2:2+n], addr); err != nil {
			s.Error("write dns error: " + err.Error())
			return
		}
	}
}
