package utils

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

type Addr []byte

const MaxAddrLen = 1 + 1 + 255 + 2

const (
	AddrTypeIPv4   = 1
	AddrTypeDomain = 3
	AddrTypeIPv6   = 4
)

var ErrInvalidAddrType = errors.New("invalid address type")

func (addr Addr) Network() string {
	return "socks"
}

func (addr Addr) String() string {
	switch addr[0] {
	case AddrTypeIPv4:
		return net.JoinHostPort(net.IP(addr[1:1+net.IPv4len]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(addr[1+net.IPv4len:]))))
	case AddrTypeDomain:
		return net.JoinHostPort(string(addr[2:2+addr[1]]), strconv.Itoa(int(binary.BigEndian.Uint16(addr[2+addr[1]:]))))
	case AddrTypeIPv6:
		return net.JoinHostPort(net.IP(addr[1:1+net.IPv6len]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(addr[1+net.IPv6len:]))))
	default:
		return ""
	}
}

func ReadAddr(conn net.Conn) (Addr, error) {
	return ReadAddrBuffer(conn, make([]byte, MaxAddrLen))
}
func ReadAddrBuffer(conn net.Conn, addr []byte) (Addr, error) {
	_, err := io.ReadFull(conn, addr[:2])
	if err != nil {
		return nil, err
	}

	switch addr[0] {
	case AddrTypeIPv4:
		n := 1 + net.IPv4len + 2
		_, err := io.ReadFull(conn, addr[2:n])
		if err != nil {
			return nil, err
		}

		return addr[:n], nil
	case AddrTypeDomain:
		n := 1 + 1 + int(addr[1]) + 2
		_, err := io.ReadFull(conn, addr[2:n])
		if err != nil {
			return nil, err
		}

		return addr[:n], nil
	case AddrTypeIPv6:
		n := 1 + net.IPv6len + 2
		_, err := io.ReadFull(conn, addr[2:n])
		if err != nil {
			return nil, err
		}

		return addr[:n], nil
	default:
		return nil, ErrInvalidAddrType
	}
}

var ErrInvalidAddrLen = errors.New("invalid address length")

func ParseAddr(addr []byte) (Addr, error) {
	if len(addr) < 1+1+1+2 {
		return nil, ErrInvalidAddrLen
	}

	switch addr[0] {
	case AddrTypeIPv4:
		n := 1 + net.IPv4len + 2
		if len(addr) < n {
			return nil, ErrInvalidAddrLen
		}

		return addr[:n], nil
	case AddrTypeDomain:
		n := 1 + 1 + int(addr[1]) + 2
		if len(addr) < n {
			return nil, ErrInvalidAddrLen
		}

		return addr[:n], nil
	case AddrTypeIPv6:
		n := 1 + net.IPv6len + 2
		if len(addr) < n {
			return nil, ErrInvalidAddrLen
		}

		return addr[:n], nil
	default:
		return nil, ErrInvalidAddrType
	}
}

func ResolveTCPAddr(addr Addr) (*net.TCPAddr, error) {
	switch addr[0] {
	case AddrTypeIPv4:
		return &net.TCPAddr{IP: net.IP(addr[1 : 1+net.IPv4len]), Port: int(binary.BigEndian.Uint16(addr[1+net.IPv4len:]))}, nil
	case AddrTypeDomain:
		return net.ResolveTCPAddr("tcp", addr.String())
	case AddrTypeIPv6:
		return &net.TCPAddr{IP: net.IP(addr[1 : 1+net.IPv6len]), Port: int(binary.BigEndian.Uint16(addr[1+net.IPv6len:]))}, nil
	default:
		return nil, ErrInvalidAddrType
	}
}

func ResolveUDPAddr(addr Addr) (*net.UDPAddr, error) {
	switch addr[0] {
	case AddrTypeIPv4:
		return &net.UDPAddr{IP: net.IP(addr[1 : 1+net.IPv4len]), Port: int(binary.BigEndian.Uint16(addr[1+net.IPv4len:]))}, nil
	case AddrTypeDomain:
		return net.ResolveUDPAddr("udp", addr.String())
	case AddrTypeIPv6:
		return &net.UDPAddr{IP: net.IP(addr[1 : 1+net.IPv6len]), Port: int(binary.BigEndian.Uint16(addr[1+net.IPv6len:]))}, nil
	default:
		return nil, ErrInvalidAddrType
	}
}

func ResolveAddr(addr net.Addr) (Addr, error) {
	if a, ok := addr.(Addr); ok {
		return a, nil
	}

	return ResolveAddrBuffer(addr, make([]byte, MaxAddrLen))
}
func ResolveAddrBuffer(addr net.Addr, b []byte) (Addr, error) {
	if a, ok := addr.(*net.TCPAddr); ok {
		if ip := a.IP.To4(); ip != nil {
			b[0] = AddrTypeIPv4
			copy(b[1:], ip)
			b[1+net.IPv4len], b[1+net.IPv4len+1] = byte(a.Port>>8), byte(a.Port)

			return b[:1+net.IPv4len+2], nil
		} else {
			ip = a.IP.To16()

			b[0] = AddrTypeIPv6
			copy(b[1:], ip)
			b[1+net.IPv6len], b[1+net.IPv6len+1] = byte(a.Port>>8), byte(a.Port)

			return b[:1+net.IPv6len+2], nil
		}
	}

	if a, ok := addr.(*net.UDPAddr); ok {
		if ip := a.IP.To4(); ip != nil {
			b[0] = AddrTypeIPv4
			copy(b[1:], ip)
			b[1+net.IPv4len], b[1+net.IPv4len+1] = byte(a.Port>>8), byte(a.Port)

			return b[:1+net.IPv4len+2], nil
		} else {
			ip = a.IP.To16()

			b[0] = AddrTypeIPv6
			copy(b[1:], ip)
			b[1+net.IPv6len], b[1+net.IPv6len+1] = byte(a.Port>>8), byte(a.Port)

			return b[:1+net.IPv6len+2], nil
		}
	}

	if a, ok := addr.(Addr); ok {
		return a, nil
	}

	return nil, ErrInvalidAddrType
}
