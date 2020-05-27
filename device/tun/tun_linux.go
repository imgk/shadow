// +build linux

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifreqSize       = unix.IFNAMSIZ + 64
)

func NewDevice(name string) (*Device, error) {
	nfd, err := unix.Open(cloneDevicePath, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CreateTUN(%q) failed; %s does not exist", name, cloneDevicePath)
		}
		return nil, err
	}

	ifrf := struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}{}

	nameBytes := []byte(name)
	if len(nameBytes) >= unix.IFNAMSIZ {
		return nil, errors.New("interface name too long")
	}
	copy(ifrf.Name[:], nameBytes)
	ifrf.Flags = unix.IFF_TUN //| unix.IFF_NO_PI (disabled for TUN status hack)

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(nfd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return nil, os.NewSyscallError("ioctl: TUNSETIFF", errno)
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.

	if err = unix.SetNonblock(nfd, true); err != nil {
		return nil, err
	}

	dev := &Device{
		File:   os.NewFile(uintptr(nfd), cloneDevicePath),
		Name:   name,
		active: make(chan struct{}),
		rBuf:   make([]byte, 4+1500),
		wBuf:   make([]byte, 4+1500),
	}

	return dev, nil
}

func (d *Device) NewDeviceFromFd(fd uint) (*Device, error) {
	var ifrf = struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}{}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNGETIFF, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return nil, errno
	}

	if ifrf.Flags&unix.IFF_TUN == 0 || ifrf.Flags&unix.IFF_NO_PI != 0 {
		return nil, errors.New("Only tun device and pi mode supported")
	}

	i := bytes.IndexByte(ifrf.Name[:], 0)
	if i == -1 {
		i = 0
	}

	dev := &Device{
		File:   os.NewFile(uintptr(fd), cloneDevicePath),
		Name:   string(ifrf.Name[:i]),
		active: make(chan struct{}),
		rBuf:   make([]byte, 4+1500),
		wBuf:   make([]byte, 4+1500),
	}

	return dev, nil
}

func NewDeviceFromFile(fd *os.File) (*Device, error) {
	dev := &Device{
		File:   fd,
		Name:   fd.Name(),
		active: make(chan struct{}),
		rBuf:   make([]byte, 4+1500),
		wBuf:   make([]byte, 4+1500),
	}

	return dev, nil
}

//https://github.com/daaku/go.ip/blob/master/ip.go
func (d *Device) Activate(addr, mask, gateway string) error {
	if ip4, err := Parse4(addr); err != nil {
		return err
	} else {
		d.Conf4.Addr = ip4
	}

	if ip4, err := Parse4(mask); err != nil {
		return err
	} else {
		d.Conf4.Mask = ip4
	}

	if ip4, err := Parse4(gateway); err != nil {
		return err
	} else {
		d.Conf4.Gateway = ip4
	}

	fd4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd4)

	fd := uintptr(fd4)

	nameBytes := [16]byte{}
	copy(nameBytes[:], []byte(d.Name))

	ifra := struct {
		Name [16]byte
		Addr unix.RawSockaddrInet4
		_    [8]byte
	}{
		Name: nameBytes,
		Addr: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   d.Conf4.Addr,
		},
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFADDR", errno)
	}

	ifra.Addr.Addr = d.Conf4.Mask
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFNETMASK", errno)
	}

	ifrf := struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}{
		Name: nameBytes,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCGIFFLAGS", errno)
	}

	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFFLAGS", errno)
	}

	return nil
}

//https://github.com/torvalds/linux/blob/master/include/uapi/linux/route.h
type rtentry struct {
	_       [8]byte
	Dst     unix.RawSockaddrInet4
	Gateway unix.RawSockaddrInet4
	Genmask unix.RawSockaddrInet4
	Flags   uint16
	_       [14]byte
	Tos     uint8
	Class   uint8
	_       [3]int16
	Metric  int16
	_       [6]byte
	Dev     uintptr
	Mtu     uint64
	Window  uint64
	Irtt    uint16
	_       [6]byte
}

func (d *Device) AddRoute(cidr []string) error {
	return d.modifyRouteTable(cidr, unix.SIOCADDRT)
}

func (d *Device) DelRoute(cidr []string) error {
	return d.modifyRouteTable(cidr, unix.SIOCDELRT)
}

func (d *Device) modifyRouteTable(cidr []string, cmd uintptr) error {
	fd4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd4)

	fd := uintptr(fd4)

	nameBytes := [16]byte{}
	copy(nameBytes[:], []byte(d.Name))

	route := rtentry{
		Dst: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   [4]byte{},
		},
		Gateway: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   d.Conf4.Gateway,
		},
		Genmask: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   [4]byte{},
		},
		Flags: unix.RTF_UP | unix.RTF_GATEWAY,
		Dev:   uintptr(unsafe.Pointer(&nameBytes)),
	}

	for _, item := range cidr {
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return err
		}

		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			return fmt.Errorf("not ipv4 address: %v", item)
		}
		mask := ipNet.Mask

		route.Dst.Addr = [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
		route.Genmask.Addr = [4]byte{mask[0], mask[1], mask[2], mask[3]}

		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, cmd, uintptr(unsafe.Pointer(&route))); errno != 0 {
			return os.NewSyscallError("ioctl: SIOCADDRT/SIOCDELRT", errno)
		}
	}

	return nil
}

func (d *Device) GetTunName() (string, error) {
	conn, err := d.File.SyscallConn()
	if err != nil {
		return "", err
	}

	ifr := struct {
		Name [16]byte
		_    [24]byte
	}{}

	var errno unix.Errno
	fn := func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, unix.TUNGETIFF, uintptr(unsafe.Pointer(&ifr)))
	}

	if err := conn.Control(fn); err != nil {
		return "", fmt.Errorf("sysconn control func error: %w", err)
	}
	if errno != 0 {
		return "", os.NewSyscallError("ioctl: TUNGETIFF", errno)
	}

	i := bytes.IndexByte(ifr.Name[:], 0)
	if i == -1 {
		return "", fmt.Errorf("get interface name error")
	}

	return string(ifr.Name[:i]), nil
}

func (d *Device) Write(b []byte) (int, error) {
	n := copy(d.wBuf[4:], b)

	switch d.wBuf[4] >> 4 {
	case ipv6.Version:
		d.wBuf[2] = 0x86
		d.wBuf[3] = 0xdd
	case ipv4.Version:
		d.wBuf[2] = 0x08
		d.wBuf[3] = 0x00
	default:
		return 0, errors.New("invalid packet")
	}

	n, err := d.File.Write(d.wBuf[:4+n])
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			err = io.EOF
		}

		select {
		case <-d.active:
			return n - 4, io.EOF
		default:
			return n - 4, err
		}
	}

	return n - 4, nil
}

func (d *Device) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		nr, er := r.Read(d.wBuf[4:])
		if nr > 0 {
			switch d.wBuf[4] >> 4 {
			case ipv6.Version:
				d.wBuf[2] = 0x86
				d.wBuf[3] = 0xdd
			case ipv4.Version:
				d.wBuf[2] = 0x08
				d.wBuf[3] = 0x00
			default:
				return 0, errors.New("invalid packet")
			}

			nw, ew := d.File.Write(d.wBuf[:4+nr])
			n += int64(nw - 4)

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
