package utils

import (
	"net"
	"sync"

	"github.com/imgk/shadow/utils/iptree"
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

type IPFilter struct {
	sync.RWMutex
	*iptree.Tree
	mode bool
}

func NewIPFilter() *IPFilter {
	f := &IPFilter{
		RWMutex: sync.RWMutex{},
		Tree:    iptree.NewTree(),
		mode:    true,
	}

	return f
}

func (f *IPFilter) String() string {
	s := ""
	ch := f.Tree.Enumerate()

	for p := range ch {
		s += p.Key.String()
	}

	return s
}

func (f *IPFilter) SetMode(mode bool) {
	f.Lock()
	f.UnsafeSetMode(mode)
	f.Unlock()
}

func (f *IPFilter) UnsafeSetMode(mode bool) {
	f.mode = mode
}

func (f *IPFilter) Reset() {
	f.Lock()
	f.UnsafeReset()
	f.Unlock()
}

func (f *IPFilter) UnsafeReset() {
	f.Tree = iptree.NewTree()
}

func (f *IPFilter) Add(s string) error {
	f.Lock()
	err := f.UnsafeAdd(s)
	f.Unlock()

	return err
}

func (f *IPFilter) UnsafeAdd(s string) error {
	ip := net.ParseIP(s)
	if ip != nil {
		return f.AddIP(ip)
	}

	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return err
	}

	return f.AddCIDR(ipNet)
}

func (f *IPFilter) AddIP(ip net.IP) error {
	f.Tree.InplaceInsertIP(ip, nil)
	return nil
}

func (f *IPFilter) AddCIDR(ip *net.IPNet) error {
	f.Tree.InplaceInsertNet(ip, nil)
	return nil
}

func (f *IPFilter) Sort() {
	f.Lock()
	f.UnsafeSort()
	f.Unlock()
}

func (f *IPFilter) UnsafeSort() {
}

func (f *IPFilter) Lookup(ip net.IP) bool {
	f.RLock()
	_, b := f.Tree.GetByIP(ip)
	f.RUnlock()

	return b == f.mode
}
