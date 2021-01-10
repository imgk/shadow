package netstack

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/netstack/core"
)

var _ common.PacketConn = (*FakeUDPConn)(nil)

type FakeUDPConn struct {
	*core.UDPConn
	fake net.Addr
	real net.Addr
}

func NewFakeUDPConn(conn *core.UDPConn, target net.Addr, addr net.Addr) *FakeUDPConn {
	return &FakeUDPConn{UDPConn: conn, fake: target, real: addr}
}

func (conn *FakeUDPConn) ReadTo(b []byte) (int, net.Addr, error) {
	n, _, err := conn.UDPConn.ReadTo(b)
	return n, conn.real, err
}

func (conn *FakeUDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return conn.UDPConn.WriteFrom(b, conn.fake)
}

func (conn *FakeUDPConn) LocalAddr() net.Addr {
	return conn.real
}

var _ common.PacketConn = (*UDPConn)(nil)

type UDPConn struct {
	*core.UDPConn
	Stack *Stack
}

func NewUDPConn(conn *core.UDPConn, stack *Stack) *UDPConn {
	return &UDPConn{UDPConn: conn, Stack: stack}
}

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

func (conn *UDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	if saddr, ok := addr.(common.Addr); ok {
		target, err := common.ResolveUDPAddr(saddr)
		if err != nil {
			return 0, fmt.Errorf("resolve udp addr error: %w", err)
		}
		return conn.UDPConn.WriteFrom(b, target)
	}

	return conn.UDPConn.WriteFrom(b, addr)
}

type Logger struct {
	Logger *zap.Logger
}

func (l *Logger) Error(s string) {
	l.Logger.Error(s)
}

func (l *Logger) Info(s string) {
	l.Logger.Info(s)
}

var _ core.Handler = (*Stack)(nil)

type Stack struct {
	core.Stack
	handler common.Handler

	resolver common.Resolver
	tree     *common.DomainTree
	hijack   bool

	counter uint16
}

func NewStack(handler common.Handler, resolver common.Resolver, tree *common.DomainTree, hijack bool) *Stack {
	return &Stack{
		handler:  handler,
		resolver: resolver,
		tree:     tree,
		hijack:   hijack,
		counter:  uint16(time.Now().Unix()),
	}
}

func (s *Stack) Start(dev common.Device, logger *zap.Logger) error {
	return s.Stack.Start(dev.(core.Device), s, &Logger{Logger: logger})
}

func (s *Stack) Handle(conn net.Conn, target *net.TCPAddr) {
	addr, err := s.LookupAddr(target)
	if err == ErrNotFake {
		if ip := target.IP.To4(); ip != nil {
			if (ip[0] == 224) ||
				(ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255) ||
				(ip[0] == 239 && ip[1] == 255 && ip[2] == 255 && ip[3] == 250) ||
				(ip[0] == 10) ||
				(ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)) ||
				(ip[0] == 192 && ip[1] == 168) ||
				(ip[0] == 169 && ip[1] == 254) {
				s.Info(fmt.Sprintf("ignore conns to %v", target))
				conn.Close()
				return
			}
		} else {
			ip := target.IP.To16()
			if ip[0] == 0xfe && ip[1] == 0x80 ||
				(ip[0] == 0xff && ip[1] == 0x02) {
				s.Info(fmt.Sprintf("ignore conns to %v", target))
				conn.Close()
				return
			}
		}

		s.Info(fmt.Sprintf("proxyd %v <-TCP-> %v", conn.RemoteAddr(), target))
		if err := s.handler.Handle(conn, target); err != nil {
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
	if err := s.handler.Handle(conn, addr); err != nil {
		s.Error(fmt.Sprintf("handle tcp error: %v", err))
	}
	return
}

func (s *Stack) HandlePacket(conn *core.UDPConn, target *net.UDPAddr) {
	if target == nil {
		s.Info(fmt.Sprintf("proxyd %v <-UDP-> 0.0.0.0:0", conn.RemoteAddr()))
		if err := s.handler.HandlePacket(NewUDPConn(conn, s)); err != nil {
			s.Error(fmt.Sprintf("handle udp error: %v", err))
		}
		return
	}

	addr, err := s.LookupAddr(target)
	if err == ErrNotFound {
		s.Error(fmt.Sprintf("%v not found", target))
		return
	}
	if err == ErrNotFake {
		if target.Port == 53 && s.hijack {
			s.Info(fmt.Sprintf("hijack %v <-UDP-> %v", conn.RemoteAddr(), target))
			s.HandleQuery(conn)
			return
		}
		if ip := target.IP.To4(); ip != nil {
			if (ip[0] == 224) ||
				(ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255) ||
				(ip[0] == 239 && ip[1] == 255 && ip[2] == 255 && ip[3] == 250) ||
				(ip[0] == 10) ||
				(ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)) ||
				(ip[0] == 192 && ip[1] == 168) ||
				(ip[0] == 169 && ip[1] == 254) {
				s.Info(fmt.Sprintf("ignore packets to %v", target))
				conn.Close()
				return
			}
		} else {
			ip := target.IP.To16()
			if ip[0] == 0xfe && ip[1] == 0x80 ||
				(ip[0] == 0xff && ip[1] == 0x02) {
				s.Info(fmt.Sprintf("ignore packets to %v", target))
				conn.Close()
				return
			}
		}

		s.Info(fmt.Sprintf("proxyd %v <-UDP-> %v", conn.RemoteAddr(), target))
		if err := s.handler.HandlePacket(NewUDPConn(conn, s)); err != nil {
			s.Error(fmt.Sprintf("handle udp error: %v", err))
		}
		return
	}

	s.Info(fmt.Sprintf("proxyd %v <-UDP-> %v", conn.RemoteAddr(), addr))
	if err := s.handler.HandlePacket(NewFakeUDPConn(conn, target, addr)); err != nil {
		s.Error(fmt.Sprintf("handle udp error: %v", err))
	}
	return
}

// handle dns queries
func (s *Stack) HandleQuery(conn *core.UDPConn) {
	defer conn.Close()

	slice := common.Get()
	defer common.Put(slice)
	b := slice.Get()
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
			if err == io.EOF {
				break
			}
			s.Error(fmt.Sprintf("read dns error: %v", err))
			break
		}

		if err := m.Unpack(b[2 : 2+n]); err != nil {
			s.Error(fmt.Sprintf("unpack message error: %v", err))
			continue
		}

		if len(m.Question) == 0 {
			s.Error("no question in message")
			continue
		}
		s.Info(fmt.Sprintf("queryd %v ask for %v", conn.RemoteAddr(), m.Question[0].Name))

		s.HandleMessage(&m)
		if m.MsgHdr.Response {
			bb, err := m.PackBuffer(b[2:])
			if err != nil {
				s.Error("append message error: " + err.Error())
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
				s.Error("resolve dns error: " + err.Error())
				continue
			}
			n = nr
		}

		if _, err := conn.WriteFrom(b[2:2+n], addr); err != nil {
			s.Error("write dns error: " + err.Error())
			break
		}
	}
}
