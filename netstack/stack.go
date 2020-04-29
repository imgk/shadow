package netstack

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/imgk/shadow/log"
	"github.com/imgk/shadow/utils"
)

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
	conns map[net.Addr]PacketConn
}

func NewStack(handler Handler, w io.Writer) *stack {
	s := &stack{
		RWMutex:   sync.RWMutex{},
		LWIPStack: core.NewLWIPStack(),
		IPFilter:  utils.NewIPFilter(),
		Handler:   handler,
		conns:     make(map[net.Addr]PacketConn),
	}

	core.RegisterTCPConnHandler(s)
	core.RegisterUDPConnHandler(s)
	core.RegisterOutputFn(w.Write)

	return s
}

type DuplexConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

func (s *stack) RedirectTCP(conn net.Conn, target *net.TCPAddr) {
	defer conn.Close()

	rc, err := net.DialTCP("tcp", nil, target)
	if err != nil {
		log.Logf("dial remote % error: %v", target, err)
		return
	}
	defer rc.Close()

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

func (s *stack) RedirectUDP(conn *DirectUDPConn) {
	b := buffer.Get().([]byte)

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
	buffer.Put(b)
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
	s.conns[conn.LocalAddr()] = conn
	s.Unlock()
}

func (s *stack) Del(conn PacketConn) {
	s.Lock()
	delete(s.conns, conn.LocalAddr())
	s.Unlock()
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
