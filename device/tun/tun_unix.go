// +build darwin linux

package tun

import "golang.zx2c4.com/wireguard/tun"

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

func (d *Device) DeviceType() string {
	return "UnixTun"
}
