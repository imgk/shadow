package netstack

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/netstack/core"
)

func NewPacketConn(conn core.PacketConn, target net.Addr, addr net.Addr, stack *Stack) common.PacketConn {
	if target == nil && addr == nil {
		return udpConn{PacketConn: conn, Stack: stack}
	}

	return fakeConn{PacketConn: conn, fake: target, real: addr}
}

type fakeConn struct {
	core.PacketConn
	fake net.Addr
	real net.Addr
}

func (conn fakeConn) ReadTo(b []byte) (int, net.Addr, error) {
	n, _, err := conn.PacketConn.ReadTo(b)
	return n, conn.real, err
}

func (conn fakeConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return conn.PacketConn.WriteFrom(b, conn.fake)
}

type udpConn struct {
	core.PacketConn
	Stack *Stack
}

func (conn udpConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
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

func (conn udpConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	if saddr, ok := addr.(common.Addr); ok {
		target, err := common.ResolveUDPAddr(saddr)
		if err != nil {
			return 0, fmt.Errorf("resolve udp addr error: %w", err)
		}
		return conn.PacketConn.WriteFrom(b, target)
	}

	return conn.PacketConn.WriteFrom(b, addr)
}

type Stack struct {
	core.Stack
	handler common.Handler

	resolver common.Resolver
	tree     *common.DomainTree

	buffer  sync.Pool
	counter uint16
}

func NewStack(handler common.Handler, dev common.Device, resolver common.Resolver, logger *zap.Logger) *Stack {
	s := &Stack{
		handler:  handler,
		resolver: resolver,
		tree:     common.NewDomainTree("."),
		buffer:   sync.Pool{New: newMessage},
		counter:  uint16(time.Now().Unix()),
	}
	s.Stack.Init(dev.(core.Device), s, logger)
	return s
}

func newMessage() interface{} {
	return make([]byte, 1024*2)
}

func (s *Stack) DomainTree() *common.DomainTree {
	return s.tree
}

func (s *Stack) Handle(conn core.Conn, target *net.TCPAddr) {
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
			if ip[0] == 0xfe && ip[1] == 0x80 {
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

func (s *Stack) HandlePacket(conn core.PacketConn, target *net.UDPAddr) {
	if target == nil {
		s.Info(fmt.Sprintf("proxyd %v <-UDP-> 0.0.0.0:0", conn.RemoteAddr()))
		if err := s.handler.HandlePacket(NewPacketConn(conn, nil, nil, s)); err != nil {
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
		if target.Port == 53 {
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
			if ip[0] == 0xfe && ip[1] == 0x80 {
				s.Info(fmt.Sprintf("ignore packets to %v", target))
				conn.Close()
				return
			}
		}

		s.Info(fmt.Sprintf("proxyd %v <-UDP-> %v", conn.RemoteAddr(), target))
		if err := s.handler.HandlePacket(NewPacketConn(conn, nil, nil, s)); err != nil {
			s.Error(fmt.Sprintf("handle udp error: %v", err))
		}
		return
	}

	s.Info(fmt.Sprintf("proxyd %v <-UDP-> %v", conn.RemoteAddr(), addr))
	if err := s.handler.HandlePacket(NewPacketConn(conn, target, addr, s)); err != nil {
		s.Error(fmt.Sprintf("handle udp error: %v", err))
	}
	return
}

func (s *Stack) HandleQuery(conn core.PacketConn) {
	defer conn.Close()

	b := s.buffer.Get().([]byte)
	m := dns.Msg{}
	defer s.buffer.Put(b)

	for {
		conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		n, addr, err := conn.ReadTo(b[2:])
		if err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
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
