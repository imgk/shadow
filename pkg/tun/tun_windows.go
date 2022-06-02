//go:build windows
// +build windows

package tun

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"unsafe"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// determineGUID is ...
// generate GUID from tun name
func determineGUID(name string) *windows.GUID {
	b := make([]byte, unsafe.Sizeof(windows.GUID{}))
	if _, err := io.ReadFull(hkdf.New(md5.New, []byte(name), nil, nil), b); err != nil {
		return nil
	}
	return (*windows.GUID)(unsafe.Pointer(&b[0]))
}

// Device is ...
type Device struct {
	// NativeTun is ...
	*tun.NativeTun
	// Name is ...
	Name string
	// MTU is ...
	MTU int
	// Conf4 is ...
	Conf4 struct {
		// Addr is ...
		Addr [4]byte
		// Mask is ...
		Mask [4]byte
		// Gateway is ...
		Gateway [4]byte
	}
	// Conf6 is ...
	Conf6 struct {
		// Addr is ...
		Addr [16]byte
		// Mask is ...
		Mask [16]byte
		// Gateway is ...
		Gateway [16]byte
	}
}

// CreateTUN is ...
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

// DeviceType is ...
func (d *Device) DeviceType() string {
	return "WinTun"
}

// Write is ...
func (d *Device) Write(b []byte) (int, error) {
	return d.NativeTun.Write(b, 0)
}

// SetInterfaceAddress is ...
// 192.168.1.11/24
// fe80:08ef:ae86:68ef::11/64
func (d *Device) SetInterfaceAddress(address string) error {
	if _, _, gateway, err := getInterfaceConfig4(address); err == nil {
		return d.setInterfaceAddress4("", address, gateway)
	}
	if _, _, gateway, err := getInterfaceConfig6(address); err == nil {
		return d.setInterfaceAddress6("", address, gateway)
	}
	return errors.New("tun device address error")
}

// setInterfaceAddress4 is ...
// https://github.com/WireGuard/wireguard-windows/blob/ef8d4f03bbb6e407bc4470b2134a9ab374155633/tunnel/addressconfig.go#L60-L168
func (d *Device) setInterfaceAddress4(addr, mask, gateway string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	addresses := append([]netip.Prefix{}, netip.MustParsePrefix(mask))

	err := luid.SetIPAddressesForFamily(windows.AF_INET, addresses)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		cleanupAddressesOnDisconnectedInterfaces(windows.AF_INET, addresses)
		err = luid.SetIPAddressesForFamily(windows.AF_INET, addresses)
	}
	if err != nil {
		return err
	}

	err = luid.SetDNS(windows.AF_INET, []netip.Addr{netip.MustParseAddr(gateway)}, []string{})
	return err
}

// setInterfaceAddress6 is ...
func (d *Device) setInterfaceAddress6(addr, mask, gateway string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	addresses := append([]netip.Prefix{}, netip.MustParsePrefix(mask))

	err := luid.SetIPAddressesForFamily(windows.AF_INET6, addresses)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		cleanupAddressesOnDisconnectedInterfaces(windows.AF_INET6, addresses)
		err = luid.SetIPAddressesForFamily(windows.AF_INET6, addresses)
	}
	if err != nil {
		return err
	}

	err = luid.SetDNS(windows.AF_INET6, []netip.Addr{netip.MustParseAddr(gateway)}, []string{})
	return err
}

// Activate is ...
func (d *Device) Activate() error {
	return nil
}

// addRouteEntry is ...
func (d *Device) addRouteEntry4(cidr []string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	routes := make(map[winipcfg.RouteData]bool, len(cidr))
	for _, item := range cidr {
		ipNet, err := netip.ParsePrefix(item)
		if err != nil {
			return fmt.Errorf("ParsePrefix error: %w", err)
		}
		routes[winipcfg.RouteData{
			Destination: ipNet,
			NextHop:     netip.IPv4Unspecified(),
			Metric:      0,
		}] = true
	}

	for r := range routes {
		if err := luid.AddRoute(r.Destination, r.NextHop, r.Metric); err != nil {
			return fmt.Errorf("AddRoute error: %w", err)
		}
	}

	return nil
}

// addRouteEntry6 is ...
func (d *Device) addRouteEntry6(cidr []string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	routes := make(map[winipcfg.RouteData]bool, len(cidr))
	for _, item := range cidr {
		ipNet, err := netip.ParsePrefix(item)
		if err != nil {
			return fmt.Errorf("ParsePrefix error: %w", err)
		}
		routes[winipcfg.RouteData{
			Destination: ipNet,
			NextHop:     netip.IPv6Unspecified(),
			Metric:      0,
		}] = true
	}

	for r := range routes {
		if err := luid.AddRoute(r.Destination, r.NextHop, r.Metric); err != nil {
			return fmt.Errorf("AddRoute error: %w", err)
		}
	}

	return nil
}

// use golang.zx2c4.com/wireguard/windows/tunnel
var _ = tunnel.UseFixedGUIDInsteadOfDeterministic

// cleanupAddressesOnDisconnectedInterfaces is ...
// https://github.com/WireGuard/wireguard-windows/blob/master/tunnel/addressconfig.go#L21
//
//go:linkname cleanupAddressesOnDisconnectedInterfaces golang.zx2c4.com/wireguard/windows/tunnel.cleanupAddressesOnDisconnectedInterfaces
func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []netip.Prefix)
