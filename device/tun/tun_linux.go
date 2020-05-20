// +build linux

package tun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

func NewDevice(name string) (*Device, error) {
	nfd, err := unix.Open(cloneDevicePath, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CreateTUN(%q) failed; %s does not exist", name, cloneDevicePath)
		}
		return nil, err
	}

	var ifr [ifReqSize]byte
	var flags uint16 = unix.IFF_TUN //| unix.IFF_NO_PI (disabled for TUN status hack)
	nameBytes := []byte(name)
	if len(nameBytes) >= unix.IFNAMSIZ {
		return nil, errors.New("interface name too long")
	}
	copy(ifr[:], nameBytes)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(nfd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return nil, errno
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(nfd), uintptr(unix.TUNSETPERSIST), 1); errno != 0 {
		return nil, os.NewSyscallError("ioctl", errno)
	}

	if err = unix.SetNonblock(nfd, true); err != nil {
		return nil, err
	}

	dev := &Device{
		Name:   name,
		active: make(chan struct{}),
		tun:    os.NewFile(uintptr(nfd), cloneDevicePath),
		rBuf:   make([]byte, 4+1500),
		wBuf:   make([]byte, 4+1500),
	}

	return dev, nil
}

func NewDeviceFromFile(fd *os.File) (*Device, error) {
	dev := &Device{
		Name:   fd.Name(),
		active: make(chan struct{}),
		tun:    fd,
		rBuf:   make([]byte, 4+1500),
		wBuf:   make([]byte, 4+1500),
	}

	return dev, nil
}

func (d *Device) Write(b []byte) (int, error) {
	n := copy(d.wBuf[4:], b)

	switch d.wBuf[4]>>4 {
	case ipv6.Version:
		d.wBuf[2] = 0x86
		d.wBuf[3] = 0xdd
	case ipv4.Version:
		d.wBuf[2] = 0x08
		d.wBuf[3] = 0x00
	default:
		return 0, errors.New("invalid packet")
	}

	n, err := d.tun.Write(d.wBuf[:4+n])
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			err = io.EOF
		}

		select {
		case <-d.active:
			return n-4, io.EOF
		default:
			return n-4, err
		}
	}

	return n-4, nil
}

func (d *Device) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		nr, er := r.Read(d.wBuf[4:])
		if nr > 0 {
			switch d.wBuf[4]>>4 {
			case ipv6.Version:
				d.wBuf[2] = 0x86
				d.wBuf[3] = 0xdd
			case ipv4.Version:
				d.wBuf[2] = 0x08
				d.wBuf[3] = 0x00
			default:
				return 0, errors.New("invalid packet")
			}

			nw, ew := d.tun.Write(d.wBuf[:4+nr])
			n += int64(nw-4)

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
