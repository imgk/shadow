package tun

import (
	"errors"
	"net"
	"unsafe"
)

// parse4 is ...
func parse4(addr string) [4]byte {
	ip := net.ParseIP(addr).To4()
	return *(*[4]byte)(unsafe.Pointer(&ip[0]))
}

// parse6 is ...
func parse6(addr string) [16]byte {
	ip := net.ParseIP(addr).To16()
	return *(*[16]byte)(unsafe.Pointer(&ip[0]))
}

// NewDevice is ...
func NewDevice(name string) (*Device, error) {
	return CreateTUN(name, 1500)
}

// NewDeviceWithMTU is ...
func NewDeviceWithMTU(name string, mtu int) (*Device, error) {
	return CreateTUN(name, mtu)
}

// SetInterfaceAddress is ...
// 192.168.1.11/24
// fe80:08ef:ae86:68ef::11/64
func (d *Device) SetInterfaceAddress(address string) error {
	if addr, mask, gateway, err := getInterfaceConfig4(address); err == nil {
		return d.setInterfaceAddress4(addr, mask, gateway)
	}
	if addr, mask, gateway, err := getInterfaceConfig6(address); err == nil {
		return d.setInterfaceAddress6(addr, mask, gateway)
	}
	return errors.New("tun device address error")
}

// AddRouteEntry is ...
// 198.18.0.0/16
// 8.8.8.8/32
func (d *Device) AddRouteEntry(cidr []string) error {
	cidr4 := make([]string, 0, len(cidr))
	cidr6 := make([]string, 0, len(cidr))
	for _, item := range cidr {
		ip, _, err := net.ParseCIDR(item)
		if err != nil {
			return err
		}
		if ip.To4() != nil {
			cidr4 = append(cidr4, item)
			continue
		}
		if ip.To16() != nil {
			cidr6 = append(cidr6, item)
			continue
		}
	}
	if err := d.addRouteEntry4(cidr4); err != nil {
		return err
	}
	err := d.addRouteEntry6(cidr6)
	return err
}

// getInterfaceConfig4 is ...
func getInterfaceConfig4(cidr string) (addr, mask, gateway string, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		err = errors.New("not ipv4 address")
		return
	}

	addr = ipv4.String()
	mask = net.IP(ipNet.Mask).String()
	ipv4 = ipNet.IP.To4()
	ipv4[net.IPv4len-1]++
	gateway = ipv4.String()

	return
}

// getInterfaceConfig6 is ...
func getInterfaceConfig6(cidr string) (addr, mask, gateway string, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	ipv6 := ip.To16()
	if ipv6 == nil {
		err = errors.New("not ipv6 address")
		return
	}

	addr = ipv6.String()
	mask = net.IP(ipNet.Mask).String()
	ipv6 = ipNet.IP.To16()
	ipv6[net.IPv6len-1]++
	gateway = ipv6.String()

	return
}
