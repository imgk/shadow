package tun

import (
	"io"

	"github.com/songgao/water"
)

type Device struct {
	Name   string
	active chan struct{}
	*water.Interface
}

func (d *Device) Read(b []byte) (int, error) {
	n, err := d.Interface.Read(b)
	if err != nil {
		select {
		case <-d.active:
			return n, io.EOF
		default:
			return n, err
		}
	}

	return n, err
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	b := make([]byte, 1500)

	for {
		nr, er := d.Read(b)
		if nr > 0 {
			nw, ew := w.Write(b[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er == io.EOF {
				break
			}

			err = er
			break
		}
	}

	return
}

func (d *Device) Write(b []byte) (int, error) {
	n, err := d.Interface.Write(b)
	if err != nil {
		select {
		case <-d.active:
			return n, io.EOF
		default:
			return n, err
		}
	}

	return n, err
}

func (d *Device) ReadFrom(r io.Reader) (n int64, err error) {
	b := make([]byte, 1500)

	for {
		nr, er := r.Read(b)
		if nr > 0 {
			nw, ew := d.Write(b[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er == io.EOF {
				break
			}

			err = er
			break
		}
	}

	return
}

func (d *Device) Close() error {
	select {
	case <-d.active:
		return nil
	default:
		close(d.active)
	}

	return d.Interface.Close()
}
