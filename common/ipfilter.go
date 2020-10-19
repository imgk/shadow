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
	Proxy  []string
	Bypass []string
	Final  bool

	reader *maxminddb.Reader
}

func NewIPFilter() *IPFilter {
	f := &IPFilter{
		RWMutex: sync.RWMutex{},
		Tree:    iptree.NewTree(),
		useGeo:  false,
	}

	return f
}

func (f *IPFilter) Close() error {
	if f.useGeo {
		return f.reader.Close()
	}
	return nil
}

func (f *IPFilter) SetGeoIP(s string) (err error) {
	f.useGeo = true
	f.reader, err = maxminddb.Open(s)
	return
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

type Record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func (f *IPFilter) Lookup(ip net.IP) bool {
	f.RLock()
	defer f.RUnlock()

	_, ok := f.Tree.GetByIP(ip)
	if !ok && f.useGeo {
		record := Record{}

		err := f.reader.Lookup(ip, &record)
		if err != nil {
			return false
		}
		code := record.Country.ISOCode

		for _, v := range f.Proxy {
			if v == code {
				return true
			}
		}
		for _, v := range f.Bypass {
			if v == code {
				return false
			}
		}
		return f.Final
	}
	return true
}
