package utils

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

func IPv4Mask(i uint32) net.IPMask {
	return net.IPMask([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

func IPv6Mask(a, b, c, d uint32) net.IPMask {
	return net.IPMask([]byte{
		byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a),
		byte(b >> 24), byte(b >> 16), byte(b >> 8), byte(b),
		byte(c >> 24), byte(c >> 16), byte(c >> 8), byte(c),
		byte(d >> 24), byte(d >> 16), byte(d >> 8), byte(d)},
	)
}

func IPv4Addr(i uint32) net.IP {
	return net.IP([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

func IPv6Addr(a, b, c, d uint32) net.IP {
	return net.IP([]byte{
		byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a),
		byte(b >> 24), byte(b >> 16), byte(b >> 8), byte(b),
		byte(c >> 24), byte(c >> 16), byte(c >> 8), byte(c),
		byte(d >> 24), byte(d >> 16), byte(d >> 8), byte(d)},
	)
}

type Element struct {
	N uint32
	R map[uint32]struct{}
	C int
}

type Element6 struct {
	N [4]uint32
	R map[[4]uint32]struct{}
	C int
}

type IPFilter struct {
	sync.RWMutex
	mode bool
	E    []*Element
	E6   []*Element6
}

func Mask4(ones int) uint32 {
	return ^uint32(0) << (32 - ones)
}

func Mask6(ones int) [4]uint32 {
	if ones < 33 {
		return [4]uint32{^uint32(0) << (32 - ones), 0, 0, 0}
	}

	if ones < 65 {
		return [4]uint32{^uint32(0), ^uint32(0) << (64 - ones), 0, 0}
	}

	if ones < 97 {
		return [4]uint32{^uint32(0), ^uint32(0), ^uint32(0) << (96 - ones), 0}
	}

	if ones < 129 {
		return [4]uint32{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0) << (128 - ones)}
	}

	return [4]uint32{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)}
}

func NewIPFilter() *IPFilter {
	f := &IPFilter{
		RWMutex: sync.RWMutex{},
		mode:    true,
		E:       make([]*Element, 32),
		E6:      make([]*Element6, 128),
	}

	// index = ones - 1
	for i := range f.E {
		f.E[i] = &Element{
			N: Mask4(i + 1),
			R: make(map[uint32]struct{}),
			C: 0,
		}
	}

	// index = ones - 1
	for i := range f.E6 {
		f.E6[i] = &Element6{
			N: Mask6(i + 1),
			R: make(map[[4]uint32]struct{}),
			C: 0,
		}
	}

	return f
}

func (f *IPFilter) String() string {
	s := ""
	for _, e := range f.E {
		s += fmt.Sprintf("Netmask: %v\n", IPv4Mask(e.N))
		for k, _ := range e.R {
			s += fmt.Sprintf("\tIP Addr: %v\n", IPv4Addr(k))
		}
	}

	for _, e := range f.E6 {
		s += fmt.Sprintf("Netmask: %v\n", IPv6Mask(e.N[0], e.N[1], e.N[2], e.N[3]))
		for k, _ := range e.R {
			s += fmt.Sprintf("\tIP Addr: %v\n", IPv6Addr(k[0], k[1], k[2], k[3]))
		}
	}

	return s
}

func (f *IPFilter) SetMode(mode bool) {
	f.Lock()
	defer f.Unlock()

	f.UnsafeSetMode(mode)
}

func (f *IPFilter) UnsafeSetMode(mode bool) {
	f.mode = mode
}

func (f *IPFilter) Reset() {
	f.Lock()
	defer f.Unlock()

	f.UnsafeReset()
}

func (f *IPFilter) UnsafeReset() {
	f.E = f.E[:0]
	for i := 0; i < 32; i++ {
		f.E = append(f.E, &Element{
			N: Mask4(i + 1),
			R: make(map[uint32]struct{}),
			C: 0,
		})
	}

	f.E6 = f.E6[:0]
	for i := 0; i < 128; i++ {
		f.E6 = append(f.E6, &Element6{
			N: Mask6(i + 1),
			R: make(map[[4]uint32]struct{}),
			C: 0,
		})
	}
}

var errInvalid = errors.New("invalid format")

func (f *IPFilter) Add(s string) error {
	f.Lock()
	defer f.Unlock()

	return f.UnsafeAdd(s)
}

func (f *IPFilter) UnsafeAdd(s string) error {
	ip := net.ParseIP(s)
	if ip != nil {
		return f.AddIP(ip)
	}

	_, ipNet, err := net.ParseCIDR(s)
	if err == nil {
		return f.AddCIDR(ipNet.IP, ipNet.Mask)
	}

	return errInvalid
}

func (f *IPFilter) AddIP(ip net.IP) error {
	ipv4 := ip.To4()
	if ipv4 == nil {
		ipv6 := ip.To16()
		addr := [4]uint32{
			(uint32(ipv6[0]) << 24) | (uint32(ipv6[1]) << 16) | (uint32(ipv6[2]) << 8) | uint32(ipv6[3]),
			(uint32(ipv6[4]) << 24) | (uint32(ipv6[5]) << 16) | (uint32(ipv6[6]) << 8) | uint32(ipv6[7]),
			(uint32(ipv6[8]) << 24) | (uint32(ipv6[9]) << 16) | (uint32(ipv6[10]) << 8) | uint32(ipv6[11]),
			(uint32(ipv6[12]) << 24) | (uint32(ipv6[13]) << 16) | (uint32(ipv6[14]) << 8) | uint32(ipv6[15]),
		}

		f.E6[127].R[addr] = struct{}{}

		return nil
	}

	addr := (uint32(ipv4[0]) << 24) | (uint32(ipv4[1]) << 16) | (uint32(ipv4[2]) << 8) | uint32(ipv4[3])
	f.E[31].R[addr] = struct{}{}

	return nil
}

func (f *IPFilter) AddCIDR(ip net.IP, mask net.IPMask) error {
	ones, bits := mask.Size()

	if bits == 128 {
		e := f.E6[ones-1]

		addr := [4]uint32{
			(uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3]),
			(uint32(ip[4]) << 24) | (uint32(ip[5]) << 16) | (uint32(ip[6]) << 8) | uint32(ip[7]),
			(uint32(ip[8]) << 24) | (uint32(ip[9]) << 16) | (uint32(ip[10]) << 8) | uint32(ip[11]),
			(uint32(ip[12]) << 24) | (uint32(ip[13]) << 16) | (uint32(ip[14]) << 8) | uint32(ip[15]),
		}

		e.R[[4]uint32{addr[0] & e.N[0], addr[1] & e.N[1], addr[2] & e.N[2], addr[3] & e.N[3]}] = struct{}{}

		return nil
	}

	e := f.E[ones-1]

	addr := (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])

	e.R[addr&e.N] = struct{}{}

	return nil
}

func (f *IPFilter) Sort() {
	f.Lock()
	defer f.Unlock()

	f.UnsafeSort()
}

func (f *IPFilter) UnsafeSort() {
	for _, e := range f.E {
		if e.C == 0 {
			e.C = len(e.R)
		}
	}

	for i := 0; i < len(f.E); i++ {
		for j := i; j < len(f.E); j++ {
			if f.E[i].C < f.E[j].C {
				f.E[i], f.E[j] = f.E[j], f.E[i]
			}
		}
	}

	for i := range f.E {
		if f.E[i].C == 0 {
			for j := i; j < len(f.E); j++ {
				f.E[j] = nil
			}
			f.E = f.E[:i]

			break
		}

		f.E[i].C = 0
	}

	for _, e := range f.E6 {
		if e.C == 0 {
			e.C = len(e.R)
		}
	}

	for i := 0; i < len(f.E6); i++ {
		for j := i; j < len(f.E6); j++ {
			if f.E6[i].C < f.E6[j].C {
				f.E6[i], f.E6[j] = f.E6[j], f.E6[i]
			}
		}
	}

	for i := range f.E6 {
		if f.E6[i].C == 0 {
			for j := i; j < len(f.E6); j++ {
				f.E6[j] = nil
			}
			f.E6 = f.E6[:i]

			break
		}

		f.E6[i].C = 0
	}
}

func (f *IPFilter) Lookup(ip net.IP) bool {
	f.RLock()
	defer f.RUnlock()

	ipv4 := ip.To4()
	if ipv4 == nil {
		ipv6 := ip.To16()
		if ipv6 == nil {
			return false == f.mode
		}

		addr := [4]uint32{
			(uint32(ipv6[0]) << 24) | (uint32(ipv6[1]) << 16) | (uint32(ipv6[2]) << 8) | uint32(ipv6[3]),
			(uint32(ipv6[4]) << 24) | (uint32(ipv6[5]) << 16) | (uint32(ipv6[6]) << 8) | uint32(ipv6[7]),
			(uint32(ipv6[8]) << 24) | (uint32(ipv6[9]) << 16) | (uint32(ipv6[10]) << 8) | uint32(ipv6[11]),
			(uint32(ipv6[12]) << 24) | (uint32(ipv6[13]) << 16) | (uint32(ipv6[14]) << 8) | uint32(ipv6[15]),
		}

		for _, e := range f.E6 {
			if _, ok := e.R[[4]uint32{addr[0] & e.N[0], addr[1] & e.N[1], addr[2] & e.N[2], addr[3] & e.N[3]}]; ok {
				e.C++
				return true == f.mode
			}
		}

		return false == f.mode
	}

	addr := (uint32(ipv4[0]) << 24) | (uint32(ipv4[1]) << 16) | (uint32(ipv4[2]) << 8) | uint32(ipv4[3])

	for _, e := range f.E {
		if _, ok := e.R[addr&e.N]; ok {
			e.C++
			return true == f.mode
		}
	}

	return false == f.mode
}
