// +build windows

package netstack

import (
	"encoding/binary"
	"net"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/imgk/shadow/dns"
	"github.com/imgk/shadow/log"
	// "github.com/imgk/shadow/netstack/core"
	"github.com/imgk/shadow/utils"
)

func (s *stack) Handle(conn net.Conn, target *net.TCPAddr) error {
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

func (s *stack) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		pc := NewUDPConn(conn, nil)
		s.Add(pc)

		log.Logf("proxy %v <-UDP-> any", conn.LocalAddr())
		go s.HandleUDP(pc)

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
