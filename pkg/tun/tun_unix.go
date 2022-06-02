//go:build darwin || linux
// +build darwin linux

package tun

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// Device is ...
type Device struct {
	// NativeTun is ...
	*tun.NativeTun
	// Namt is ...
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
	device, err := tun.CreateTUN(name, mtu)
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
	return "UnixTun"
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
