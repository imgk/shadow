// +build windows

package tun

import (
	"bytes"
	"crypto/md5"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"unsafe"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func determineGUID(name string) *windows.GUID {
	b := make([]byte, unsafe.Sizeof(windows.GUID{}))
	if _, err := io.ReadFull(hkdf.New(md5.New, []byte(name), nil, nil), b); err != nil {
		return nil
	}
	return (*windows.GUID)(unsafe.Pointer(&b[0]))
}

type Device struct {
	*tun.NativeTun
	Name  string
	MTU   int
	Conf4 struct {
		Addr    [4]byte
		Mask    [4]byte
		Gateway [4]byte
	}
	Conf6 struct {
		Addr    [16]byte
		Mask    [16]byte
		Gateway [16]byte
	}
}

func CreateTUN(name string, mtu int) (dev *Device, err error) {
	dev = &Device{}
	device, err := tun.CreateTUNWithRequestedGUID(name, determineGUID(name), mtu)
	if err != nil {
		return
	}
	dev.NativeTun = device.(*tun.NativeTun)
	if dev.Name, err = dev.NativeTun.Name(); err != nil {
		return
	}
	if dev.MTU, err = dev.NativeTun.MTU(); err != nil {
		return
	}
	return
}

func (d *Device) Read(b []byte) (int, error) {
	return d.NativeTun.Read(b, 0)
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	b := make([]byte, d.MTU)
	for {
		nr, er := d.NativeTun.Read(b, 0)
		if nr > 0 {
			nw, ew := w.Write(b[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if errors.Is(er, os.ErrClosed) {
				break
			}
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

func (d *Device) Write(b []byte) (int, error) {
	return d.NativeTun.Write(b, 0)
}

func (d *Device) ReadFrom(r io.Reader) (n int64, err error) {
	b := make([]byte, d.MTU)
	for {
		nr, er := r.Read(b)
		if nr > 0 {
			nw, ew := d.NativeTun.Write(b, 0)
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = er
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if errors.Is(er, os.ErrClosed) {
				break
			}
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

//https://github.com/WireGuard/wireguard-windows/blob/ef8d4f03bbb6e407bc4470b2134a9ab374155633/tunnel/addressconfig.go#L22-L58
func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []net.IPNet) {
	if len(addresses) == 0 {
		return
	}
	includedInAddresses := func(a net.IPNet) bool {
		// TODO: this makes the whole algorithm O(n^2). But we can't stick net.IPNet in a Go hashmap. Bummer!
		for _, addr := range addresses {
			ip := addr.IP
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			mA, _ := addr.Mask.Size()
			mB, _ := a.Mask.Size()
			if bytes.Equal(ip, a.IP) && mA == mB {
				return true
			}
		}
		return false
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			ipnet := net.IPNet{IP: ip, Mask: net.CIDRMask(int(address.OnLinkPrefixLength), 8*len(ip))}
			if includedInAddresses(ipnet) {
				iface.LUID.DeleteIPAddress(ipnet)
			}
		}
	}
}

//https://github.com/WireGuard/wireguard-windows/blob/ef8d4f03bbb6e407bc4470b2134a9ab374155633/tunnel/addressconfig.go#L60-L168
func (d *Device) setInterfaceAddress4(addr, mask, gateway string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	addresses := append([]net.IPNet{}, net.IPNet{
		IP:   net.ParseIP(addr).To4(),
		Mask: net.IPMask(net.ParseIP(mask).To4()),
	})

	err := luid.SetIPAddressesForFamily(windows.AF_INET, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(windows.AF_INET, addresses)
		err = luid.SetIPAddressesForFamily(windows.AF_INET, addresses)
	}
	if err != nil {
		return err
	}

	err = luid.SetDNSForFamily(windows.AF_INET, []net.IP{net.ParseIP(gateway).To4()})
	return err
}

func (d *Device) setInterfaceAddress6(addr, mask, gateway string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	addresses := append([]net.IPNet{}, net.IPNet{
		IP:   net.ParseIP(addr).To16(),
		Mask: net.IPMask(net.ParseIP(mask).To16()),
	})

	err := luid.SetIPAddressesForFamily(windows.AF_INET6, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(windows.AF_INET6, addresses)
		err = luid.SetIPAddressesForFamily(windows.AF_INET6, addresses)
	}
	if err != nil {
		return err
	}

	err = luid.SetDNSForFamily(windows.AF_INET6, []net.IP{net.ParseIP(gateway).To16()})
	return err
}

func (d *Device) Activate() error {
	return nil
}

func (d *Device) addRouteEntry4(cidr []string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	routes := make([]winipcfg.RouteData, 0, len(cidr))
	for _, item := range cidr {
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return err
		}
		routes = append(routes, winipcfg.RouteData{
			Destination: *ipNet,
			NextHop:     net.IPv4zero,
			Metric:      0,
		})
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Metric < routes[j].Metric ||
			bytes.Compare(routes[i].NextHop, routes[j].NextHop) == -1 ||
			bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP) == -1 ||
			bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask) == -1
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	return luid.SetRoutesForFamily(windows.AF_INET, deduplicatedRoutes)
}

func (d *Device) addRouteEntry6(cidr []string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	routes := make([]winipcfg.RouteData, 0, len(cidr))
	for _, item := range cidr {
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return err
		}
		routes = append(routes, winipcfg.RouteData{
			Destination: *ipNet,
			NextHop:     net.IPv6zero,
			Metric:      0,
		})
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Metric < routes[j].Metric ||
			bytes.Compare(routes[i].NextHop, routes[j].NextHop) == -1 ||
			bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP) == -1 ||
			bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask) == -1
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	return luid.SetRoutesForFamily(windows.AF_INET6, deduplicatedRoutes)
}
