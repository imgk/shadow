package utils

import (
	"net"
	"sync"

	"github.com/imgk/shadow/utils/iptree"
)

type IPFilter struct {
	sync.RWMutex
	Tree *iptree.Tree
}

func NewIPFilter() *IPFilter {
	f := &IPFilter{
		RWMutex: sync.RWMutex{},
		Tree:    iptree.NewTree(),
	}

	return f
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
		return f.addIP(ip)
	}

	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return err
	}

	return f.addCIDR(ipNet)
}

func (f *IPFilter) addIP(ip net.IP) error {
	f.Tree.InplaceInsertIP(ip, nil)
	return nil
}

func (f *IPFilter) addCIDR(ip *net.IPNet) error {
	f.Tree.InplaceInsertNet(ip, nil)
	return nil
}

func (f *IPFilter) Lookup(ip net.IP) bool {
	f.RLock()
	_, ok := f.Tree.GetByIP(ip)
	f.RUnlock()

	return ok
}
