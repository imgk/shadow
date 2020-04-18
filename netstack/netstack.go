package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/imgk/shadowsocks-windivert/dns"
	"github.com/imgk/shadowsocks-windivert/log"
	// "github.com/imgk/shadowsocks-windivert/netstack/core"
	"github.com/imgk/shadowsocks-windivert/utils"
)

const MaxUDPPacketSize = 16384 // Max 65536

var buffer = sync.Pool{New: func() interface{} { return make([]byte, MaxUDPPacketSize) }}

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

type DirectUDPConn struct {
	core.UDPConn
	net.PacketConn
}

func NewDirectUDPConn(conn core.UDPConn, pc net.PacketConn) *DirectUDPConn {
	return &DirectUDPConn{
		UDPConn:    conn,
		PacketConn: pc,
	}
}

func (conn *DirectUDPConn) Close() error {
	conn.UDPConn.Close()
	return conn.PacketConn.Close()
}

func (conn *DirectUDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return conn.UDPConn.WriteFrom(b, addr.(*net.UDPAddr))
}

func (conn *DirectUDPConn) WriteTo(b []byte, addr *net.UDPAddr) error {
	_, err := conn.PacketConn.WriteTo(b, addr)
	return err
}

func (conn *DirectUDPConn) ReadTo(b []byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not support")
}

func (conn *DirectUDPConn) LocalAddr() net.Addr {
	return conn.UDPConn.LocalAddr()
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
		UDPConn:    conn,
		PipeReader: r,
		PipeWriter: w,
		active:     make(chan struct{}),
		addr:       make(chan net.Addr, 1),
		target:     tgt,
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
		return 0, fmt.Errorf("resolve udp addr error: %v", err)
	}

	return conn.UDPConn.WriteFrom(data, addr)
}

func (conn *UDPConn) WriteTo(data []byte, target *net.UDPAddr) error {
	if _, err := conn.PipeWriter.Write(data); err != nil {
		select {
		case <-conn.active:
			err = io.EOF
		default:
		}

		return err
	}

	select {
	case <-conn.active:
		return io.EOF
	default:
		addr, err := dns.IPToDomainAddrBuffer(target.IP, ([]byte)(utils.GetAddr()))
		if err != nil {
			utils.PutAddr(addr)
			conn.addr <- target
		} else {
			binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))
			conn.addr <- addr
		}
	}

	return nil
}

func (conn *UDPConn) ReadTo(b []byte) (int, net.Addr, error) {
	n, err := conn.PipeReader.Read(b)
	if err != nil {
		select {
		case <-conn.active:
			err = io.EOF
		default:
		}

		return n, nil, err
	}

	addr, ok := <-conn.addr
	if ok {
		return n, addr, nil
	}

	return n, addr, io.EOF
}

func (conn *UDPConn) Close() error {
	select {
	case <-conn.active:
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
	*utils.IPFilter
	Handler
	conns map[net.Addr]utils.PacketConn
}

func NewStack(handler Handler, w io.Writer) *stack {
	s := &stack{
		RWMutex:   sync.RWMutex{},
		LWIPStack: core.NewLWIPStack(),
		IPFilter:  utils.NewIPFilter(),
		Handler:   handler,
		conns:     make(map[net.Addr]utils.PacketConn),
	}

	core.RegisterTCPConnHandler(s)
	core.RegisterUDPConnHandler(s)
	core.RegisterOutputFn(w.Write)

	return s
}

func (s *stack) Handle(conn net.Conn, target *net.TCPAddr) error {
	if !s.IPFilter.Lookup(target.IP) {
		log.Logf("direct %v <-TCP-> %v", conn.LocalAddr(), target)
		go s.RedirectTCP(conn, target)

		return nil
	}

	addr, err := dns.IPToDomainAddrBuffer(target.IP, ([]byte)(utils.GetAddr()))
	if err != nil {
		utils.PutAddr(addr)
		log.Logf("proxy %v <-TCP-> %v", conn.LocalAddr(), target)
		go s.HandleTCP(conn, target)

		return nil
	}
	binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

	log.Logf("proxy %v <-TCP-> %v", conn.LocalAddr(), addr)
	go s.HandleTCP(conn, addr)

	return nil
}

type DuplexConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

func (s *stack) RedirectTCP(conn net.Conn, target *net.TCPAddr) {
	rc, err := net.DialTCP("tcp", nil, target)
	if err != nil {
		log.Logf("dial remote % error: %v", target, err)
		return
	}

	if err := relay(conn.(DuplexConn), rc); err != nil {
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

func relay(c, rc DuplexConn) error {
	defer c.Close()
	defer rc.Close()

	errCh := make(chan error)
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

func (s *stack) HandleTCP(conn net.Conn, addr net.Addr) {
	if err := s.Handler.Handle(conn, addr); err != nil {
		log.Logf("handle tcp error: %v", err)
	}
}

func (s *stack) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		rc, err := net.ListenPacket("udp", "")
		if err != nil {
			log.Logf("listen packet conn error: %v", err)
			return err
		}

		pc := NewDirectUDPConn(conn, rc)
		s.Add(pc)

		log.Logf("direct %v <-UDP-> any", conn.LocalAddr())
		go s.RedirectUDP(pc)

		return nil
	}

	if !s.IPFilter.Lookup(target.IP) {
		rc, err := net.ListenPacket("udp", "")
		if err != nil {
			log.Logf("listen packet conn error: %v", err)
			return err
		}

		pc := NewDirectUDPConn(conn, rc)
		s.Add(pc)

		log.Logf("direct %v <-UDP-> %v", conn.LocalAddr(), target)
		go s.RedirectUDP(pc)

		return nil
	}

	addr, err := dns.IPToDomainAddrBuffer(target.IP, ([]byte)(utils.GetAddr()))
	defer utils.PutAddr(addr)
	if err != nil {
		pc := NewUDPConn(conn, target)
		s.Add(pc)

		log.Logf("proxy %v <-UDP-> %v", conn.LocalAddr(), target)
		go s.HandleUDP(pc)

		return nil
	}
	binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

	pc := NewUDPConn(conn, target)
	s.Add(pc)

	log.Logf("proxy %v <-UDP-> %v", conn.LocalAddr(), addr)
	go s.HandleUDP(pc)

	return nil
}

func (s *stack) RedirectUDP(conn *DirectUDPConn) {
	defer s.Del(conn)

	b := buffer.Get().([]byte)
	defer buffer.Put(b)

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

	conn.Close()
}

func (s *stack) HandleUDP(conn *UDPConn) {
	defer s.Del(conn)

	if err := s.Handler.HandlePacket(conn); err != nil {
		log.Logf("handle udp error: %v", err)
	}
}

func (s *stack) Add(conn utils.PacketConn) {
	s.Lock()
	defer s.Unlock()

	s.conns[conn.LocalAddr()] = conn
}

func (s *stack) Del(conn utils.PacketConn) {
	s.Lock()
	defer s.Unlock()

	delete(s.conns, conn.LocalAddr())
}

func (s *stack) ReceiveTo(conn core.UDPConn, data []byte, target *net.UDPAddr) error {
	s.RLock()
	pc, ok := s.conns[net.Addr(conn.LocalAddr())]
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
	for _, pc := range s.conns {
		pc.Close()
	}

	return s.LWIPStack.Close()
}
