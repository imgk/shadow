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
	buf  []byte
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
	dev.buf = make([]byte, 4+dev.MTU)
	dev.buff = make([]byte, 4+dev.MTU)
	return
}

func (d *Device) Read(b []byte) (n int, err error) {
	n, err = d.NativeTun.Read(d.buf, 4)
	if len(b) < n {
		err = io.ErrShortBuffer
		return
	}
	copy(b, d.buf[4:4+n])
	return
}

func (d *Device) ReadOffset(b []byte, offset int) (int, error) {
	return d.NativeTun.Read(b, offset)
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	b := d.buf
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

func (d *Device) Write(b []byte) (n int, err error) {
	n = copy(d.buff[4:], b)
	_, err = d.NativeTun.Write(d.buff[:4+n], 4)
	return 
}

func (d *Device) WriteOffset(b []byte, offset int) (int, error) {
	return d.NativeTun.Write(b, offset)
}

func (d *Device) ReadFrom(r io.Reader) (n int64, err error) {
	b := d.buff
	for {
		nr, er := r.Read(b[4:])
		if nr > 0 {
			nw, ew := d.NativeTun.Write(b[:4+nr], 4)
			if nw > 0 {
				n += int64(nw-4)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw-4 {
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
