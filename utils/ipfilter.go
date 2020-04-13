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
	return net.IPMask([]byte{})
}

func IPv4Addr(i uint32) net.IP {
	return net.IP([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

func IPv6Addr(a, b, c, d uint32) net.IP {
	return net.IP([]byte{})
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
	E  []*Element
	E6 []*Element6
}

func NewIPFilter() *IPFilter {
	f := &IPFilter{
		RWMutex: sync.RWMutex{},
		E:       make([]*Element, 32),
		E6:      make([]*Element6, 128),
	}

	mask := ^uint32(0)

	for i := range f.E {
		f.E[i] = &Element{
			N: mask << (31 - i),
			R: make(map[uint32]struct{}),
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

	return s
}

func (f *IPFilter) Reset() {
	f.Lock()
	defer f.Unlock()

	f.UnsafeReset()
}

func (f *IPFilter) UnsafeReset() {
	mask := ^uint32(0)

	f.E = f.E[:0]
	for i := 0; i < 32; i++ {
		f.E = append(f.E, &Element{
			N: mask << (31 - i),
			R: make(map[uint32]struct{}),
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

var errHasSorted = errors.New("has sorted")

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

var errInvalidIP = errors.New("invalid ip format")

func (f *IPFilter) AddIP(ip net.IP) error {
	if ip = ip.To4(); ip == nil {
		return errInvalidIP
	}

	addr := (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])
	f.E[31].R[addr] = struct{}{}

	return nil
}

var errInvalidMask = errors.New("invalid mask format")

func (f *IPFilter) AddCIDR(ip net.IP, mask net.IPMask) error {
	ones, bits := mask.Size()

	if bits == 128 {
		return errInvalidMask
	}

	e := f.E[ones-1]

	addr := (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])

	e.R[addr&e.N] = struct{}{}

	return nil
}

func (f *IPFilter) Sort() {
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
			f.E = f.E[:i]

			for j := i; j < len(f.E); j++ {
				f.E[j] = nil
			}

			break
		}

		f.E[i].C = 0
	}
}

func (f *IPFilter) Lookup(ip net.IP) bool {
	if ip = ip.To4(); ip == nil {
		return false
	}

	addr := (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])

	f.RLock()
	defer f.RUnlock()

	for _, e := range f.E {
		if _, ok := e.R[addr&e.N]; ok {
			e.C++
			return true
		}
	}

	return false
}
