// +build darwin linux

package tun

import "golang.zx2c4.com/wireguard/tun"

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
