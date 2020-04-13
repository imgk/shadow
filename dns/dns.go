package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/imgk/shadowsocks-windivert/utils"
)

var (
	counter   = uint16(time.Now().Unix())
	matchTree = utils.NewTree(".")
)

func MatchTree() *utils.Tree {
	return matchTree
}

func ParseUrl(s string) (listen, server string, err error) {
	ss := strings.Split(s, "=")

	if len(ss) != 2 {
		err = errors.New("incorrect dns config")
		return
	}

	listen = ss[0]
	server = ss[1]

	return
}

func AddrToDomainAddr(addr net.Addr, b []byte) (utils.Addr, error) {
	switch addr.(type) {
	case *net.TCPAddr:
		a, err := IPToDomainAddr(addr.(*net.TCPAddr).IP, b)
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint16(a[len(a)-2:], uint16(addr.(*net.TCPAddr).Port))
		return a, nil
	case *net.UDPAddr:
		a, err := IPToDomainAddr(addr.(*net.UDPAddr).IP, b)
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint16(a[len(a)-2:], uint16(addr.(*net.UDPAddr).Port))
		return a, nil
	default:
		return nil, errors.New("not support")
	}
}

func IPToDomainAddr(addr net.IP, b []byte) (utils.Addr, error) {
	if ip := addr.To4(); ip != nil {
		if ip[0] != 44 || ip[1] != 44 {
			return nil, fmt.Errorf("%v not found", addr)
		}

		s := matchTree.Load(fmt.Sprintf("%d.%d.44.44.in-addr.arpa.", ip[3], ip[2]))
		if v, ok := s.(*dnsmessage.PTRResource); ok {
			b[0] = utils.AddrTypeDomain
			b[1] = byte(v.PTR.Length)
			n := copy(b[2:], v.PTR.Data[:v.PTR.Length])

			return b[:n+4], nil
		}

		return nil, fmt.Errorf("%v not found", addr)
	}

	return nil, fmt.Errorf("%v not found", addr)
}

var errZeroLength = errors.New("length of questions in dns message is 0")

func ResolveDNS(m *dnsmessage.Message) (*dnsmessage.Message, error) {
	if len(m.Questions) == 0 {
		return m, errZeroLength
	}

	name := m.Questions[0].Name.String()
	switch s := matchTree.Load(name); s.(type) {
	case string:
		switch v := s.(string); v {
		case "PROXY":
			switch m.Questions[0].Type {
			case dnsmessage.TypeA:
				typeA := &dnsmessage.AResource{A: [4]byte{44, 44, uint8(counter >> 8), uint8(counter)}}
				matchTree.Store(name, typeA)

				typePTR := &dnsmessage.PTRResource{PTR: m.Questions[0].Name}
				matchTree.Store(fmt.Sprintf("%d.%d.44.44.in-addr.arpa.", uint8(counter), uint8(counter>>8)), typePTR)

				counter++

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
				Body: s.(*dnsmessage.PTRResource),
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
				Body: s.(*dnsmessage.AResource),
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
