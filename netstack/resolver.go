package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"

	"github.com/imgk/shadow/utils"
)

func (s *Stack) LookupAddr(addr net.Addr) (net.Addr, error) {
	switch addr.(type) {
	case *net.TCPAddr:
		buf, err := s.LookupIP(addr.(*net.TCPAddr).IP)
		if err != nil {
			return addr, err
		}
		binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(addr.(*net.TCPAddr).Port))
		return buf, nil
	case *net.UDPAddr:
		buf, err := s.LookupIP(addr.(*net.UDPAddr).IP)
		if err != nil {
			return addr, err
		}
		binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(addr.(*net.UDPAddr).Port))
		return buf, nil
	case utils.Addr:
		return addr, nil
	default:
		return addr, errors.New("not support")
	}
}

var (
	ErrNotFake  = errors.New("not fake")
	ErrNotFound = errors.New("not found")
)

func (s *Stack) LookupIP(addr net.IP) (utils.Addr, error) {
	if ip := addr.To4(); ip != nil {
		if ip[0] != 198 || ip[1] != 18 {
			return nil, ErrNotFake
		}

		option := s.DomainTree.Load(fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", ip[3], ip[2]))
		if rr, ok := option.(*dns.PTR); ok {
			b := make([]byte, utils.MaxAddrLen)
			b[0] = utils.AddrTypeDomain
			b[1] = byte(len(rr.Ptr))
			n := copy(b[2:], rr.Ptr[:])
			return b[:2+n+2], nil
		}
		return nil, ErrNotFound
	}
	return nil, ErrNotFake
}

func (s *Stack) HandleMessage(m *dns.Msg) {
	option := s.DomainTree.Load(m.Question[0].Name)
	switch option.(type) {
	case string:
		if ok := s.HandleMessageByRule(m, option.(string)); ok {
			return
		}
	case *dns.A:
		switch m.Question[0].Qtype {
		case dns.TypeA:
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], option.(*dns.A))
		case dns.TypeAAAA:
			m.MsgHdr.Rcode = dns.RcodeRefused
		default:
			m.MsgHdr.Rcode = dns.RcodeRefused
		}
	case *dns.AAAA:
		switch m.Question[0].Qtype {
		case dns.TypeA:
			m.MsgHdr.Rcode = dns.RcodeRefused
		case dns.TypeAAAA:
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], option.(*dns.AAAA))
		default:
			m.MsgHdr.Rcode = dns.RcodeRefused
		}
	case *dns.PTR:
		switch m.Question[0].Qtype {
		case dns.TypePTR:
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], option.(*dns.PTR))
		default:
			m.MsgHdr.Rcode = dns.RcodeRefused
		}
	case Both:
		switch m.Question[0].Qtype {
		case dns.TypeA:
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], option.(Both).A)
		case dns.TypeAAAA:
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], option.(Both).AAAA)
		default:
			m.MsgHdr.Rcode = dns.RcodeRefused
		}
	default:
		return
	}

	m.MsgHdr.Response = true
	m.MsgHdr.Authoritative = false
	m.MsgHdr.Truncated = false
	m.MsgHdr.RecursionAvailable = false
}

type Both struct {
	A    *dns.A
	AAAA *dns.AAAA
}

func (s *Stack) HandleMessageByRule(m *dns.Msg, option string) bool {
	switch option {
	case "PROXY":
		s.counter++

		rrA := &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			A: net.IP([]byte{198, 18, byte(s.counter >> 8), byte(s.counter)}),
		}
		s.DomainTree.Store(rrA.Hdr.Name, rrA)

		rrPTR := &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", uint8(s.counter), uint8(s.counter>>8)),
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Ptr: m.Question[0].Name,
		}
		s.DomainTree.Store(rrPTR.Hdr.Name, rrPTR)

		switch m.Question[0].Qtype {
		case dns.TypeA:
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], rrA)
		case dns.TypeAAAA:
			m.MsgHdr.Rcode = dns.RcodeRefused
		default:
			m.MsgHdr.Rcode = dns.RcodeRefused
		}
	case "DIRECT":
		return true
	case "BLOCKED":
		rrA := &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			A: net.IPv4zero,
		}

		rrAAAA := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			AAAA: net.IPv6zero,
		}

		s.DomainTree.Store(rrA.Hdr.Name, Both{A: rrA, AAAA: rrAAAA})

		switch m.Question[0].Qtype {
		case dns.TypeA:
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], rrA)
		case dns.TypeAAAA:
			m.MsgHdr.Rcode = dns.RcodeSuccess
			m.Answer = append(m.Answer[:0], rrAAAA)
		default:
			m.MsgHdr.Rcode = dns.RcodeRefused
		}
	default:
		return true
	}

	return false
}
