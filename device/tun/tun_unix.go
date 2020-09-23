// +build darwin linux

package tun

import (
	"errors"
	"io"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

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
	buff []byte
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
	dev.buff = make([]byte, 4+dev.MTU)
	return
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	b := make([]byte, 4+d.MTU)
	for {
		nr, er := d.NativeTun.Read(b, 4)
		if nr > 0 {
			nw, ew := w.Write(b[4 : 4+nr])
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
	n := copy(d.buff[4:], b)
	return d.NativeTun.Write(d.buff[:4+n], 4)
}
