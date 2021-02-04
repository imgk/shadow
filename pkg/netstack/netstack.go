package netstack

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/logger"
	"github.com/imgk/shadow/pkg/netstack/core"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/resolver"
	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/pkg/suffixtree"
)

var (
	_ gonet.PacketConn = (*FakeUDPConn)(nil)
	_ gonet.PacketConn = (*UDPConn)(nil)
	_ core.Handler     = (*Stack)(nil)
)

// Device is ...
type Device interface {
	io.Closer
	core.Device
}

// FakeUDPConn is ...
type FakeUDPConn struct {
	*core.UDPConn
	fake net.Addr
	real net.Addr
}

// NewFakeUDPConn is ...
func NewFakeUDPConn(conn *core.UDPConn, target net.Addr, addr net.Addr) *FakeUDPConn {
	return &FakeUDPConn{UDPConn: conn, fake: target, real: addr}
}

// ReadTo is ...
func (conn *FakeUDPConn) ReadTo(b []byte) (int, net.Addr, error) {
	n, _, err := conn.UDPConn.ReadTo(b)
	return n, conn.real, err
}

// WriteFrom is ...
func (conn *FakeUDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return conn.UDPConn.WriteFrom(b, conn.fake)
}

// LocalAddr is ...
func (conn *FakeUDPConn) LocalAddr() net.Addr {
	return conn.real
}

// UDPConn is ...
type UDPConn struct {
	*core.UDPConn
	Stack *Stack
}

// NewUDPConn is ...
func NewUDPConn(conn *core.UDPConn, stack *Stack) *UDPConn {
	return &UDPConn{UDPConn: conn, Stack: stack}
}

// ReadTo is ...
func (conn *UDPConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = conn.UDPConn.ReadTo(b)
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

// WriteFrom is ...
func (conn *UDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	if nAddr, ok := addr.(*socks.Addr); ok {
		target, err := socks.ResolveUDPAddr(nAddr)
		if err != nil {
			return 0, fmt.Errorf("resolve udp addr error: %w", err)
		}
		return conn.UDPConn.WriteFrom(b, target)
	}

	return conn.UDPConn.WriteFrom(b, addr)
}

// Stack is core.Handler
type Stack struct {
	// Stack is ...
	core.Stack
	handler gonet.Handler

	resolver resolver.Resolver
	tree     *suffixtree.DomainTree
	hijack   bool

	counter uint16
}

// NewStack is ....
func NewStack(handler gonet.Handler, resolver resolver.Resolver, tree *suffixtree.DomainTree, hijack bool) *Stack {
	return &Stack{
		handler:  handler,
		resolver: resolver,
		tree:     tree,
		hijack:   hijack,
		counter:  uint16(time.Now().Unix()),
	}
}

// Start is ...
func (s *Stack) Start(dev Device, lg logger.Logger) error {
	device, ok := dev.(core.Device)
	if !ok {
		return errors.New("device type error")
	}
	logg, ok := lg.(core.Logger)
	if !ok {
		return errors.New("logger type error")
	}
	return s.Stack.Start(device, s, logg)
}

// Handle handles net.Conn
func (s *Stack) Handle(conn net.Conn, target *net.TCPAddr) {
	addr, err := s.LookupAddr(target)
	if err == ErrNotFake {
		if ipv4 := target.IP.To4(); ipv4 != nil {
			if ipv4[0] == 224 ||
				(ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255) ||
				(ipv4[0] == 239 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 250) {
				s.Info("ignore conns to %v", target)
				conn.Close()
				return
			}
		} else {
			ipv6 := target.IP.To16()
			if ipv6[0] == 0xff && ipv6[1] == 0x02 {
				s.Info("ignore conns to %v", target)
				conn.Close()
				return
			}
		}

		s.Info("proxyd %v <-TCP-> %v", conn.RemoteAddr(), target)
		if err := s.handler.Handle(conn, target); err != nil {
			s.Error("handle tcp error: %v", err)
		}
		return
	}
	if err == ErrNotFound {
		s.Error("handle tcp error: target %v %v", target, err)
		conn.Close()
		return
	}

	s.Info("proxyd %v <-TCP-> %v", conn.RemoteAddr(), addr)
	if err := s.handler.Handle(conn, addr); err != nil {
		s.Error("handle tcp error: %v", err)
	}
	return
}

// HandlePacket handles core.UDPConn
func (s *Stack) HandlePacket(conn *core.UDPConn, target *net.UDPAddr) {
	if target == nil {
		s.Info("proxyd %v <-UDP-> 0.0.0.0:0", conn.RemoteAddr())
		if err := s.handler.HandlePacket(NewUDPConn(conn, s)); err != nil {
			s.Error("handle udp error: %v", err)
		}
		return
	}

	addr, err := s.LookupAddr(target)
	if err == ErrNotFound {
		s.Error("%v not found", target)
		return
	}
	if err == ErrNotFake {
		if target.Port == 53 && s.hijack {
			s.Info("hijack %v <-UDP-> %v", conn.RemoteAddr(), target)
			s.HandleQuery(conn)
			return
		}
		if ipv4 := target.IP.To4(); ipv4 != nil {
			if ipv4[0] == 224 ||
				(ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255) ||
				(ipv4[0] == 239 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 250) {
				s.Info("ignore packets to %v", target)
				conn.Close()
				return
			}
		} else {
			ipv6 := target.IP.To16()
			if ipv6[0] == 0xff && ipv6[1] == 0x02 {
				s.Info("ignore packets to %v", target)
				conn.Close()
				return
			}
		}

		s.Info("proxyd %v <-UDP-> %v", conn.RemoteAddr(), target)
		if err := s.handler.HandlePacket(NewUDPConn(conn, s)); err != nil {
			s.Error("handle udp error: %v", err)
		}
		return
	}

	s.Info("proxyd %v <-UDP-> %v", conn.RemoteAddr(), addr)
	if err := s.handler.HandlePacket(NewFakeUDPConn(conn, target, addr)); err != nil {
		s.Error("handle udp error: %v", err)
	}
	return
}

// HandleQuery handles dns queries
func (s *Stack) HandleQuery(conn *core.UDPConn) {
	defer conn.Close()

	const MaxMessageSize = 2 << 10
	sc, b := pool.Pool.Get(MaxMessageSize)
	defer pool.Pool.Put(sc)
	m := dns.Msg{}

	for {
		conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		n, addr, err := conn.ReadTo(b[2:])
		if err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
			s.Error("read dns error: %v", err)
			break
		}

		if err := m.Unpack(b[2 : 2+n]); err != nil {
			s.Error("unpack message error: %v", err)
			continue
		}

		if len(m.Question) == 0 {
			s.Error("no question in message")
			continue
		}
		s.Info("queryd %v ask for %v", conn.RemoteAddr(), m.Question[0].Name)

		s.HandleMessage(&m)
		if m.MsgHdr.Response {
			bb, err := m.PackBuffer(b[2:])
			if err != nil {
				s.Error("append message error: %v", err)
				continue
			}
			n = len(bb)
		} else {
			nr, err := s.resolver.Resolve(b, n)
			if err != nil {
				if ne := net.Error(nil); errors.As(err, &ne) {
					if ne.Timeout() {
						continue
					}
				}
				s.Error("resolve dns error: %v", err)
				continue
			}
			n = nr
		}

		if _, err := conn.WriteFrom(b[2:2+n], addr); err != nil {
			s.Error("write dns error: %v", err)
			break
		}
	}
}
