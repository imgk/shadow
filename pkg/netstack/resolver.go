package netstack

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"

	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/pkg/suffixtree"
)

// LookupAddr converts fake ip to real domain address
func (s *Stack) LookupAddr(addr net.Addr) (net.Addr, error) {
	if nAddr, ok := addr.(*net.TCPAddr); ok {
		sAddr, err := s.LookupIP(nAddr.IP)
		if err != nil {
			return addr, err
		}
		sAddr.Addr = append(sAddr.Addr, byte(nAddr.Port>>8), byte(nAddr.Port))
		return sAddr, nil
	}

	if nAddr, ok := addr.(*net.UDPAddr); ok {
		sAddr, err := s.LookupIP(nAddr.IP)
		if err != nil {
			return addr, err
		}
		sAddr.Addr = append(sAddr.Addr, byte(nAddr.Port>>8), byte(nAddr.Port))
		return sAddr, nil
	}

	if _, ok := addr.(*socks.Addr); ok {
		return addr, nil
	}

	return addr, errors.New("address type not support")
}

var (
	// ErrNotFake is ...
	ErrNotFake = errors.New("not fake")
	// ErrNotFound is ...
	ErrNotFound = errors.New("not found")
)

// LookupIP converts fake ip to real domain address
func (s *Stack) LookupIP(addr net.IP) (*socks.Addr, error) {
	if ipv4 := addr.To4(); ipv4 != nil {
		if ipv4[0] != 198 || ipv4[1] != 18 {
			return nil, ErrNotFake
		}
		ss := fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", ipv4[3], ipv4[2])
		if de, ok := s.tree.Load(ss).(*suffixtree.DomainEntry); ok {
			if de.PTR.Hdr.Ttl != 1 {
				return nil, ErrNotFound
			}
			b := append(make([]byte, 0, socks.MaxAddrLen), socks.AddrTypeDomain, byte(len(de.PTR.Ptr)))
			return &socks.Addr{Addr: append(b, de.PTR.Ptr[:]...)}, nil
		}
		return nil, ErrNotFound
	}
	return nil, ErrNotFake
}

// HandleMessage handles dns.Msg
func (s *Stack) HandleMessage(m *dns.Msg) {
	de, ok := s.tree.Load(m.Question[0].Name).(*suffixtree.DomainEntry)
	if !ok {
		return
	}

	switch m.Question[0].Qtype {
	case dns.TypeA:
		if de.A.Hdr.Ttl == 1 {
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], &de.A)
		} else {
			switch de.Rule {
			case "PROXY":
				s.counter++

				entry := &suffixtree.DomainEntry{
					PTR: dns.PTR{
						Hdr: dns.RR_Header{
							Name:   fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", uint8(s.counter), uint8(s.counter>>8)),
							Rrtype: dns.TypePTR,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						Ptr: m.Question[0].Name,
					},
				}
				s.tree.Store(entry.PTR.Hdr.Name, entry)

				entry = &suffixtree.DomainEntry{
					Rule: "PROXY",
					A: dns.A{
						Hdr: dns.RR_Header{
							Name:   m.Question[0].Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						A: net.IP([]byte{198, 18, byte(s.counter >> 8), byte(s.counter)}),
					},
				}
				s.tree.Store(entry.A.Hdr.Name, entry)

				m.MsgHdr.Rcode = dns.RcodeSuccess
				m.Answer = append(m.Answer[:0], &entry.A)
			case "BLOCKED":
				entry := &suffixtree.DomainEntry{
					Rule: "BLOCKED",
					A: dns.A{
						Hdr: dns.RR_Header{
							Name:   m.Question[0].Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						A: net.IPv4zero,
					},
					AAAA: dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   m.Question[0].Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						AAAA: net.IPv6zero,
					},
				}
				s.tree.Store(entry.A.Hdr.Name, entry)

				m.MsgHdr.Rcode = dns.RcodeSuccess
				m.Answer = append(m.Answer[:0], &entry.A)
			default:
				return
			}
		}
	case dns.TypeAAAA:
		if de.AAAA.Hdr.Ttl == 1 {
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], &de.AAAA)
		} else {
			switch de.Rule {
			case "PROXY":
				m.MsgHdr.Rcode = dns.RcodeRefused
			case "BLOCKED":
				entry := &suffixtree.DomainEntry{
					Rule: "BLOCKED",
					A: dns.A{
						Hdr: dns.RR_Header{
							Name:   m.Question[0].Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						A: net.IPv4zero,
					},
					AAAA: dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   m.Question[0].Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						AAAA: net.IPv6zero,
					},
				}
				s.tree.Store(entry.AAAA.Hdr.Name, entry)

				m.MsgHdr.Rcode = dns.RcodeSuccess
				m.Answer = append(m.Answer[:0], &entry.AAAA)
			default:
				return
			}
		}
	case dns.TypePTR:
		if de.PTR.Hdr.Ttl == 1 {
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], &de.PTR)
		} else {
			m.MsgHdr.Rcode = dns.RcodeRefused
		}
	}

	m.MsgHdr.Response = true
	m.MsgHdr.Authoritative = false
	m.MsgHdr.Truncated = false
	m.MsgHdr.RecursionAvailable = false
}
