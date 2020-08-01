// +build darwin linux

package tun

import (
	"errors"
	"io"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

type Device struct {
	Device *tun.NativeTun
	Name   string
	MTU    int
	Conf4  struct {
		Addr    [4]byte
		Mask    [4]byte
		Gateway [4]byte
	}
	Conf6 struct {
		Addr    [16]byte
		Mask    [16]byte
		Gateway [16]byte
	}
	buff []byte
}

func CreateTUN(name string, mtu int) (dev *Device, err error) {
	dev = &Device{}
	device, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return
	}
	dev.Device = device.(*tun.NativeTun)
	if dev.Name, err = dev.Device.Name(); err != nil {
		return
	}
	if dev.MTU, err = dev.Device.MTU(); err != nil {
		return
	}
	dev.buff = make([]byte, 4+dev.MTU)
	return
}

func CreateTUNFromFile(file *os.File, mtu int) (dev *Device, err error) {
	dev = &Device{}
	device, err := tun.CreateTUNFromFile(file, mtu)
	if err != nil {
		return
	}
	dev.Device = device.(*tun.NativeTun)
	if dev.Name, err = dev.Device.Name(); err != nil {
		return
	}
	if dev.MTU, err = dev.Device.MTU(); err != nil {
		return
	}
	dev.buff = make([]byte, 4+dev.MTU)
	return
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	b := make([]byte, 4+d.MTU)
	for {
		nr, er := d.Device.Read(b, 4)
		if nr > 0 {
			nw, ew := w.Write(b[4 : 4+nr])
			if nw > 0 {
				n += int64(nw)
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
			if ew != nil {
				err = ew
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
	n := copy(d.buff[4:], b)
	return d.Device.Write(d.buff[:4+n], 4)
}
