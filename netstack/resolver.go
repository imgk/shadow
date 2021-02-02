package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"

	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/pkg/suffixtree"
)

// LookupAddr converts fake ip to real domain address
func (s *Stack) LookupAddr(addr net.Addr) (net.Addr, error) {
	switch addr.(type) {
	case *net.TCPAddr:
		nAddr, err := s.LookupIP(addr.(*net.TCPAddr).IP)
		if err != nil {
			return addr, err
		}
		buf := nAddr.Addr
		binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(addr.(*net.TCPAddr).Port))
		return nAddr, nil
	case *net.UDPAddr:
		nAddr, err := s.LookupIP(addr.(*net.UDPAddr).IP)
		if err != nil {
			return addr, err
		}
		buf := nAddr.Addr
		binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(addr.(*net.UDPAddr).Port))
		return nAddr, nil
	case *socks.Addr:
		return addr, nil
	default:
		return addr, errors.New("address not support")
	}
}

var (
	// ErrNotFake is ...
	ErrNotFake = errors.New("not fake")
	// ErrNotFound is ...
	ErrNotFound = errors.New("not found")
)

// LookupIP converts fake ip to real domain address
func (s *Stack) LookupIP(addr net.IP) (*socks.Addr, error) {
	if ip := addr.To4(); ip != nil {
		if ip[0] != 198 || ip[1] != 18 {
			return nil, ErrNotFake
		}

		if opt := s.tree.Load(fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", ip[3], ip[2])); opt != nil {
			de := opt.(*suffixtree.DomainEntry)

			b := make([]byte, socks.MaxAddrLen)
			b[0] = socks.AddrTypeDomain
			b[1] = byte(len(de.PTR.Ptr))
			n := copy(b[2:], de.PTR.Ptr[:])
			return &socks.Addr{Addr: b[:2+n+2]}, nil
		}
		return nil, ErrNotFound
	}
	return nil, ErrNotFake
}

// HandleMessage handles dns.Msg
func (s *Stack) HandleMessage(m *dns.Msg) {
	opt := s.tree.Load(m.Question[0].Name)
	if opt == nil {
		return
	}

	de := opt.(*suffixtree.DomainEntry)
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
