package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

func Parse4(addr string) ([4]byte, error) {
	if ip := net.ParseIP(addr).To4(); ip != nil {
		return [4]byte{ip[0], ip[1], ip[2], ip[3]}, nil
	}

	return [4]byte{}, fmt.Errorf("parse addr: %v error", addr)
}

func Parse6(addr string) ([16]byte, error) {
	if ip := net.ParseIP(addr).To16(); ip != nil {
		return [16]byte{ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]}, nil
	}

	return [16]byte{}, fmt.Errorf("parse addr: %v error", addr)
}

type Device struct {
	*os.File
	Name  string
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
	active chan struct{}
	rBuf   []byte
	wBuf   []byte
}

func (d *Device) Read(b []byte) (int, error) {
	n, err := d.File.Read(d.rBuf)
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
		nr, er := d.File.Read(d.rBuf)
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

	return d.File.Close()
}
