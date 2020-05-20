// +build windows

package netstack

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/imgk/shadow/dns"
	"github.com/imgk/shadow/log"
	"github.com/imgk/shadow/utils"
)

type stack struct {
	sync.RWMutex
	core.LWIPStack
	Handler
	conns map[net.Addr]PacketConn
}

func NewStack(handler Handler, w io.Writer) *stack {
	s := &stack{
		RWMutex:   sync.RWMutex{},
		LWIPStack: core.NewLWIPStack(),
		Handler:   handler,
		conns:     make(map[net.Addr]PacketConn),
	}

	core.RegisterTCPConnHandler(s)
	core.RegisterUDPConnHandler(s)
	core.RegisterOutputFn(w.Write)

	return s
}

func (s *stack) Handle(conn net.Conn, target *net.TCPAddr) error {
	addr, err := dns.IPToDomainAddrBuffer(target.IP, make([]byte, utils.MaxAddrLen))
	if err != nil {
		log.Logf("proxy %v <-TCP-> %v", conn.LocalAddr(), target)
		go s.HandleTCP(conn, target)

		return nil
	}
	binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

	log.Logf("proxy %v <-TCP-> %v", conn.LocalAddr(), addr)
	go s.HandleTCP(conn, addr)

	return nil
}

func (s *stack) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		pc := NewUDPConn(conn, nil)
		s.Add(pc)

		log.Logf("proxy %v <-UDP-> any", conn.LocalAddr())
		go s.HandleUDP(pc)

		return nil
	}

	if target.Port == 53 {
		pc := NewUDPConn(conn, target)
		s.Add(pc)

		log.Logf("hijack %v <-UDP-> %v", conn.LocalAddr(), target)
		go s.HandleMessage(pc)

		return nil
	}

	addr, err := dns.IPToDomainAddrBuffer(target.IP, make([]byte, utils.MaxAddrLen))
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
