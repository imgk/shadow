// +build darwin

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

const utunControlName = "com.apple.net.utun_control"

// _CTLIOCGINFO value derived from /usr/include/sys/{kern_control,ioccom}.h
const _CTLIOCGINFO = (0x40000000 | 0x80000000) | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3

var sockaddrCtlSize uintptr = 32

// sockaddr_ctl specifeid in /usr/include/sys/kern_control.h
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

func NewDevice(name string) (*Device, error) {
	ifIndex := -1
	if name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return nil, fmt.Errorf("Interface name must be utun[0-9]*")
		}
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)

	if err != nil {
		return nil, err
	}

	var ctlInfo = &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}

	copy(ctlInfo.ctlName[:], []byte(utunControlName))

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(_CTLIOCGINFO),
		uintptr(unsafe.Pointer(ctlInfo)),
	)

	if errno != 0 {
		return nil, fmt.Errorf("_CTLIOCGINFO: %v", errno)
	}

	sc := sockaddrCtl{
		scLen:     uint8(sockaddrCtlSize),
		scFamily:  unix.AF_SYSTEM,
		ssSysaddr: 2,
		scID:      ctlInfo.ctlID,
		scUnit:    uint32(ifIndex) + 1,
	}

	scPointer := unsafe.Pointer(&sc)

	_, _, errno = unix.RawSyscall(
		unix.SYS_CONNECT,
		uintptr(fd),
		uintptr(scPointer),
		uintptr(sockaddrCtlSize),
	)

	if errno != 0 {
		return nil, fmt.Errorf("SYS_CONNECT: %v", errno)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}

	name, err = GetTunName(uintptr(fd))

	dev := &Device{
		Name:   name,
		active: make(chan struct{}),
		tun:    os.NewFile(uintptr(fd), name),
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

func GetTunName(fd uintptr) (string, error) {
	var ifName struct {
		name [16]byte
	}
	ifNameSize := uintptr(16)

	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		fd,
		2, /* #define SYSPROTO_CONTROL 2 */
		2, /* #define UTUN_OPT_IFNAME 2 */
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameSize)), 0)
	if errno != 0 {
		return "", fmt.Errorf("SYS_GETSOCKOPT: %v", errno)
	}

	return string(ifName.name[:ifNameSize-1]), nil
}

func (d *Device) Write(b []byte) (int, error) {
	n := copy(d.wBuf[4:], b)

	switch d.wBuf[4]>>4 {
	case ipv6.Version:
		d.wBuf[3] = unix.AF_INET6
	case ipv4.Version:
		d.wBuf[3] = unix.AF_INET
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
				d.wBuf[3] = unix.AF_INET6
			case ipv4.Version:
				d.wBuf[3] = unix.AF_INET
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
