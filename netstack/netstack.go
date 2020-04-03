package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/imgk/shadowsocks-windivert/dns"
	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/utils"
)

type Device interface {
	io.Reader
	io.WriterTo
	io.Writer
	io.ReaderFrom
	io.Closer
}

type Handler interface {
	Handle(net.Conn, net.Addr) error
	HandlePacket(utils.PacketConn) error
}

type UDPConn struct {
	core.UDPConn
	*io.PipeReader
	*io.PipeWriter
	active chan struct{}
	addr   chan net.Addr
	target *net.UDPAddr
}

func NewUDPConn(conn core.UDPConn, tgt *net.UDPAddr) *UDPConn {
	r, w := io.Pipe()

	return &UDPConn{
		UDPConn: conn,
		PipeReader: r,
		PipeWriter: w,
		active: make(chan struct{}),
		addr: make(chan net.Addr, 1),
		target: tgt,
	}
}

func (conn *UDPConn) LocalAddr() net.Addr {
	return conn.UDPConn.LocalAddr()
}

func (conn *UDPConn) WriteFrom(data []byte, src net.Addr) (int, error) {
	if conn.target != nil {
		return conn.UDPConn.WriteFrom(data, conn.target)
	}

	addr, err := utils.ResolveUDPAddr(src.(utils.Addr))
	if err != nil {
		return 0, fmt.Errorf("resolve tcp addr error: %v", err)
	}

	return conn.UDPConn.WriteFrom(data, addr)
}

func (conn *UDPConn) WriteTo(data []byte, tgt net.Addr) error {
	_, err := conn.PipeWriter.Write(data)
	if err != nil {
		if err == io.ErrClosedPipe {
			err = io.EOF
		}

		return err
	}

	select {
	case <- conn.active:
		return io.EOF
	default:
		conn.addr <- tgt
	}

	return nil
}

func (conn *UDPConn) ReadTo(b []byte) (int, net.Addr, error) {
	n, err := conn.PipeReader.Read(b)
	if err != nil {
		if err == io.ErrClosedPipe {
			err = io.EOF
		}

		return n, nil, err
	}

	return n, <- conn.addr, nil
}

func (conn *UDPConn) Close() error {
	select {
	case <- conn.active:
		return nil
	default:
		close(conn.active)
		close(conn.addr)
	}

	conn.PipeReader.Close()
	conn.PipeWriter.Close()

	return conn.UDPConn.Close()
}

type Stack interface {
	io.Reader
	io.WriterTo
	io.Writer
	io.ReaderFrom
	io.Closer
}

type stack struct {
	sync.RWMutex
	core.LWIPStack
	Handler
	conns map[core.UDPConn]utils.PacketConn
}

func NewStack(handler Handler, w io.Writer) Stack {
	s := &stack{
		RWMutex:   sync.RWMutex{},
		LWIPStack: core.NewLWIPStack(),
		Handler:   handler,
		conns:     make(map[core.UDPConn]utils.PacketConn),
	}

	core.RegisterTCPConnHandler(s)
	core.RegisterUDPConnHandler(s)
	core.RegisterOutputFn(w.Write)

	return s
}

func (s *stack) Handle(conn net.Conn, target *net.TCPAddr) error {
	addr, err := dns.IPToDomainAddr(target.IP, make([]byte, utils.MaxAddrLen))
	if err != nil {
		return fmt.Errorf("lookup original address error: %v", err)
	}
	binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

	log.Logf("proxy %v <-TCP-> %v", conn.LocalAddr(), addr)
	go func() {
		if err := s.Handler.Handle(conn, addr); err != nil {
			log.Logf("handle tcp error: %v", err)
		}
	}()

	return nil
}

func (s *stack) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return errors.New("nil target")
	}

	pc := NewUDPConn(conn, target)

	s.Lock()
	s.conns[conn] = pc
	s.Unlock()

	addr, err := dns.IPToDomainAddr(target.IP, make([]byte, utils.MaxAddrLen))
	if err != nil {
		return fmt.Errorf("lookup original address error: %v", err)
	}
	binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

	log.Logf("proxy %v <-UDP-> %v", conn.LocalAddr(), addr)
	go func() {
		if err := s.Handler.HandlePacket(pc); err != nil {
			log.Logf("handle udp error: %v", err)
		}

		s.Lock()
		delete(s.conns, conn)
		s.Unlock()
	}()

	return nil
}

func (s *stack) ReceiveTo(conn core.UDPConn, data []byte, target *net.UDPAddr) error {
	addr, err := dns.IPToDomainAddr(target.IP, make([]byte, utils.MaxAddrLen))
	if err != nil {
		return fmt.Errorf("lookup original address error: %v", err)
	}
	binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

	s.RLock()
	pc, ok := s.conns[conn]
	s.RUnlock()

	if !ok {
		return fmt.Errorf("connection from %v to %v does not exist", conn.LocalAddr(), target)
	}

	return pc.WriteTo(data, addr)
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
	return s.LWIPStack.Close()
}
