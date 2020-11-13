// +build windows

package common

import (
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"

	"github.com/imgk/shadow/common/iptree"
)

type IPFilter struct {
	sync.RWMutex
	Tree *iptree.Tree

	useGeo bool
	rules  map[string]bool
	final  bool

	reader *maxminddb.Reader
}

func NewIPFilter() *IPFilter {
	f := &IPFilter{
		RWMutex: sync.RWMutex{},
		Tree:    iptree.NewTree(),
		useGeo:  false,
		rules:   make(map[string]bool),
	}

	return f
}

func (f *IPFilter) Close() error {
	if f.useGeo {
		return f.reader.Close()
	}
	return nil
}

func (f *IPFilter) SetGeoIP(s string, proxy, bypass []string, final bool) (err error) {
	f.Lock()
	f.useGeo = true
	f.reader, err = maxminddb.Open(s)
	for _, v := range proxy {
		f.rules[v] = true
	}
	for _, v := range bypass {
		f.rules[v] = false
	}
	f.final = final
	f.Unlock()
	return
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
	defer f.RUnlock()

	_, ok := f.Tree.GetByIP(ip)
	if ok {
		return true
	}

	type Record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	if f.useGeo {
		record := Record{}
		if err := f.reader.Lookup(ip, &record); err != nil {
			return f.final
		}

		b, ok := f.rules[record.Country.ISOCode]
		if ok {
			return b
		}
		return f.final
	}

	return false
}
