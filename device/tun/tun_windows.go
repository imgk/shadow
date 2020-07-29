// +build windows

package tun

import (
	"io"

	"golang.zx2c4.com/wireguard/tun"
)

type Device struct {
	tun.Device
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
	if dev.Device, err = tun.CreateTUN(name, mtu); err != nil {
		return
	}
	if dev.Name, err = dev.Device.Name(); err != nil {
		return
	}
	if dev.MTU, err = dev.Device.MTU(); err != nil {
		return
	}
	return
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	b := make([]byte, d.MTU)
	for {
		nr, er := d.Device.Read(b, 0)
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
			if err != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

func (d *Device) Write(b []byte) (int, error) {
	return d.Device.Write(b, 0)
}

func (d *Device) Activate(addr, mask, gateway string) error {
	return nil
}

func (d *Device) AddRouteEntry(cidr []string) error {
	return d.modifyRouteTable(cidr, 0)
}

func (d *Device) DelRouteEntry(cidr []string) error {
	return d.modifyRouteTable(cidr, 1)
}

func (d *Device) modifyRouteTable(cidr []string, cmd uintptr) error {
	return nil
}
