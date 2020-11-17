// +build !shadow_gvisor

package core

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/eycorsican/go-tun2socks/core"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

type Stack struct {
	*zap.Logger
	Device  Device
	Handler Handler
	Stack   core.LWIPStack

	mtu   int32
	mutex sync.Mutex
	conns map[core.UDPConn]*UDPConn
}

func (s *Stack) Start(device Device, handler Handler, logger *zap.Logger) error {
	s.Logger = logger

	s.Device = device
	s.Handler = handler
	s.Stack = core.NewLWIPStack()
	s.conns = make(map[core.UDPConn]*UDPConn)

	core.RegisterOutputFn(device.Write)
	core.RegisterTCPConnHandler(s)
	core.RegisterUDPConnHandler(s)

	go func(s *Stack, wt io.WriterTo) {
		if _, err := wt.WriteTo(s.Stack); err != nil {
			s.Error(fmt.Sprintf("netstack exit error: %v", err))
		}
	}(s, device)
	return nil
}

func (s *Stack) Close() error {
	for _, conn := range s.conns {
		conn.Close()
	}
	return multierr.Combine(s.Logger.Sync(), s.Stack.Close())
}

func (s *Stack) Handle(conn net.Conn, target *net.TCPAddr) error {
	go s.Handler.Handle(TCPConn{TCPConn: conn.(core.TCPConn)}, target)
	return nil
}

func (s *Stack) Get(k core.UDPConn) (*UDPConn, bool) {
	s.mutex.Lock()
	conn, ok := s.conns[k]
	s.mutex.Unlock()
	return conn, ok
}

func (s *Stack) Add(k core.UDPConn, conn *UDPConn) {
	s.mutex.Lock()
	s.conns[k] = conn
	s.mutex.Unlock()
}

func (s *Stack) Del(k core.UDPConn) {
	s.mutex.Lock()
	delete(s.conns, k)
	s.mutex.Unlock()
}

func (s *Stack) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	pc := NewUDPConn(conn, target, s)
	s.Add(conn, pc)
	go s.Handler.HandlePacket(pc, target)
	return nil
}

func (s *Stack) ReceiveTo(conn core.UDPConn, data []byte, target *net.UDPAddr) error {
	pc, ok := s.Get(conn)
	if ok {
		pc.HandlePacket(data, target)
		return nil
	}
	return nil
}

// TCPConn
type TCPConn struct {
	core.TCPConn
}

func (conn TCPConn) RemoteAddr() net.Addr {
	return conn.TCPConn.LocalAddr()
}

func (conn TCPConn) LocalAddr() net.Addr {
	return conn.TCPConn.RemoteAddr()
}

// UDP Packet
type Packet struct {
	Addr *net.UDPAddr
	Byte []byte
}

// UDPConn
type UDPConn struct {
	deadlineTimer

	core.UDPConn
	stack  *Stack
	addr   *net.UDPAddr
	closed chan struct{}
	stream chan Packet
	read   chan struct{}
}

func NewUDPConn(c core.UDPConn, addr *net.UDPAddr, stack *Stack) *UDPConn {
	conn := &UDPConn{
		UDPConn: c,
		stack:   stack,
		addr:    addr,
		closed:  make(chan struct{}),
		stream:  make(chan Packet),
		read:    make(chan struct{}),
	}
	conn.deadlineTimer.init()
	return conn
}

func (conn *UDPConn) Close() error {
	select {
	case <-conn.closed:
		return nil
	default:
		close(conn.closed)
	}

	conn.stack.Del(conn.UDPConn)
	return conn.UDPConn.Close()
}

func (conn *UDPConn) LocalAddr() net.Addr {
	return conn.addr
}

func (conn *UDPConn) RemoteAddr() net.Addr {
	return conn.UDPConn.LocalAddr()
}

func (conn *UDPConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	deadline := conn.readCancel()
	select {
	case <-deadline:
		err = timeoutError{}
	case <-conn.closed:
		err = io.EOF
	case packet := <-conn.stream:
		n = copy(b, packet.Byte)
		addr = packet.Addr
		select {
		case <-conn.closed:
		case conn.read <- struct{}{}:
		}
	}

	return
}

func (conn *UDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return conn.UDPConn.WriteFrom(b, addr.(*net.UDPAddr))
}

func (conn *UDPConn) HandlePacket(b []byte, addr *net.UDPAddr) {
	select {
	case <-conn.closed:
	case conn.stream <- Packet{Addr: addr, Byte: b}:
		select {
		case <-conn.closed:
		case <-conn.read:
		}
	}
}
