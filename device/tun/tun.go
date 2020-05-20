package tun

import (
	"errors"
	"io"
	"os"
)

type Device struct {
	Name   string
	active chan struct{}
	tun    *os.File
	rBuf   []byte
	wBuf   []byte
}

func (d *Device) Read(b []byte) (int, error) {
	n, err := d.tun.Read(d.rBuf)
	n = copy(b, d.rBuf[4:n])
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			err = io.EOF
		}

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
	for {
		nr, er := d.tun.Read(d.rBuf)
		if nr > 0 {
			nw, ew := w.Write(d.rBuf[4:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			err = er
			break
		}
	}

	if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
		err = nil
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

	return d.tun.Close()
}
