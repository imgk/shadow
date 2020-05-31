package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/imgk/shadow/utils"
)

func (s *stack) SetResolver(server string) (err error) {
	s.Resolver, err = utils.NewResolver(server)
	return
}

func (s *stack) AddrToDomainAddr(addr net.Addr) (utils.Addr, error) {
	switch addr.(type) {
	case *net.TCPAddr:
		a, err := s.IPToDomainAddr(addr.(*net.TCPAddr).IP)
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint16(a[len(a)-2:], uint16(addr.(*net.TCPAddr).Port))

		return a, nil
	case *net.UDPAddr:
		a, err := s.IPToDomainAddr(addr.(*net.UDPAddr).IP)
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint16(a[len(a)-2:], uint16(addr.(*net.UDPAddr).Port))

		return a, nil
	default:
		return nil, errors.New("not support")
	}
}

func (s *stack) IPToDomainAddr(addr net.IP) (utils.Addr, error) {
	return s.IPToDomainAddrBuffer(addr, make([]byte, utils.MaxAddrLen))
}

func (s *stack) IPToDomainAddrBuffer(addr net.IP, b []byte) (utils.Addr, error) {
	if ip := addr.To4(); ip != nil {
		if ip[0] != 44 || ip[1] != 44 {
			return b, fmt.Errorf("%v not found", addr)
		}

		option := s.Tree.Load(fmt.Sprintf("%d.%d.44.44.in-addr.arpa.", ip[3], ip[2]))
		if v, ok := option.(*dnsmessage.PTRResource); ok {
			b = append(b[:0], utils.AddrTypeDomain, byte(v.PTR.Length))
			b = append(b, v.PTR.Data[:v.PTR.Length]...)
			b = append(b, 0, 0)

			return b, nil
		}

		return b, fmt.Errorf("%v not found", addr)
	}

	return b, fmt.Errorf("%v not found", addr)
}

var errZeroLength = errors.New("length of questions in dns message is 0")

func (s *stack) ResolveDNS(m *dnsmessage.Message) (*dnsmessage.Message, error) {
	if len(m.Questions) == 0 {
		return m, errZeroLength
	}

	name := m.Questions[0].Name.String()
	switch option := s.Tree.Load(name); option.(type) {
	case string:
		switch v := option.(string); v {
		case "PROXY":
			switch m.Questions[0].Type {
			case dnsmessage.TypeA:
				typeA := &dnsmessage.AResource{A: [4]byte{44, 44, uint8(s.counter >> 8), uint8(s.counter)}}
				s.Tree.Store(name, typeA)

				typePTR := &dnsmessage.PTRResource{PTR: m.Questions[0].Name}
				s.Tree.Store(fmt.Sprintf("%d.%d.44.44.in-addr.arpa.", uint8(s.counter), uint8(s.counter>>8)), typePTR)

				s.counter++

				m.Header.RCode = dnsmessage.RCodeSuccess
				m.Answers = append(m.Answers[:0], dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  m.Questions[0].Name,
						Type:  m.Questions[0].Type,
						Class: m.Questions[0].Class,
						TTL:   1,
					},
					Body: typeA,
				})
			case dnsmessage.TypeAAAA:
				m.Header.RCode = dnsmessage.RCodeRefused
			default:
				m.Header.RCode = dnsmessage.RCodeRefused
			}
		case "DIRECT":
			return m, nil
		case "BLOCKED":
			switch m.Questions[0].Type {
			case dnsmessage.TypeA:
				m.Header.RCode = dnsmessage.RCodeSuccess
				m.Answers = append(m.Answers[:0], dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  m.Questions[0].Name,
						Type:  m.Questions[0].Type,
						Class: m.Questions[0].Class,
						TTL:   1,
					},
					Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
				})
			case dnsmessage.TypeAAAA:
				m.Header.RCode = dnsmessage.RCodeRefused
			default:
				m.Header.RCode = dnsmessage.RCodeRefused
			}
		default:
			return m, nil
		}
	case *dnsmessage.PTRResource:
		switch m.Questions[0].Type {
		case dnsmessage.TypePTR:
			m.Header.RCode = dnsmessage.RCodeSuccess
			m.Answers = append(m.Answers[:0], dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  m.Questions[0].Name,
					Type:  m.Questions[0].Type,
					Class: m.Questions[0].Class,
					TTL:   1,
				},
				Body: option.(*dnsmessage.PTRResource),
			})
		default:
			m.Header.RCode = dnsmessage.RCodeRefused
		}
	case *dnsmessage.AResource:
		switch m.Questions[0].Type {
		case dnsmessage.TypeA:
			m.Header.RCode = dnsmessage.RCodeSuccess
			m.Answers = append(m.Answers[:0], dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  m.Questions[0].Name,
					Type:  m.Questions[0].Type,
					Class: m.Questions[0].Class,
					TTL:   1,
				},
				Body: option.(*dnsmessage.AResource),
			})
		case dnsmessage.TypeAAAA:
			m.Header.RCode = dnsmessage.RCodeRefused
		default:
			m.Header.RCode = dnsmessage.RCodeRefused
		}
	case *dnsmessage.AAAAResource:
		m.Header.RCode = dnsmessage.RCodeRefused
	default:
		return m, nil
	}

	m.Header.Response = true
	m.Header.Authoritative = false
	m.Header.Truncated = false
	m.Header.RecursionAvailable = false

	return m, nil
}
