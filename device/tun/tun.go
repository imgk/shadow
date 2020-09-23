package tun

import (
	"errors"
	"net"
	"unsafe"
)

func Parse4(addr string) [4]byte {
	ip := net.ParseIP(addr).To4()
	return *(*[4]byte)(unsafe.Pointer(&ip[0]))
}

func Parse6(addr string) [16]byte {
	ip := net.ParseIP(addr).To16()
	return *(*[16]byte)(unsafe.Pointer(&ip[0]))
}

func NewDevice(name string) (*Device, error) {
	return CreateTUN(name, 1500)
}

func NewDeviceWithMTU(name string, mtu int) (*Device, error) {
	return CreateTUN(name, mtu)
}

func (d *Device) SetInterfaceAddress(address string) error {
	if addr, mask, gateway, err := getInterfaceConfig4(address); err == nil {
		return d.setInterfaceAddress4(addr, mask, gateway)
	}
	if addr, mask, gateway, err := getInterfaceConfig6(address); err == nil {
		return d.setInterfaceAddress6(addr, mask, gateway)
	}
	return errors.New("tun device address error")
}

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

func getInterfaceConfig4(cidr string) (addr, mask, gateway string, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	ip = ip.To4()
	if ip == nil {
		err = errors.New("not ipv4 address")
		return
	}

	addr = ip.String()
	mask = net.IP(ipNet.Mask).String()
	ip = ipNet.IP.To4()
	ip[3] += 1
	gateway = ip.String()

	return
}

func getInterfaceConfig6(cidr string) (addr, mask, gateway string, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	ip = ip.To16()
	if ip == nil {
		err = errors.New("not ipv6 address")
		return
	}

	addr = ip.String()
	mask = net.IP(ipNet.Mask).String()
	ip = ipNet.IP.To16()
	ip[15] += 1
	gateway = ip.String()

	return
}
