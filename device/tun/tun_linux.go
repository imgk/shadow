// +build linux

package tun

import (
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// https://github.com/daaku/go.ip/blob/master/ip.go
func (d *Device) setInterfaceAddress4(addr, mask, gateway string) (err error) {
	d.Conf4.Addr = Parse4(addr)
	d.Conf4.Mask = Parse4(mask)
	d.Conf4.Gateway = Parse4(gateway)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	type ifreqaddr struct {
		Name [16]byte
		Addr unix.RawSockaddrInet4
		_    [8]byte
	}

	ifra := ifreqaddr{
		Addr: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
		},
	}
	copy(ifra.Name[:], []byte(d.Name))

	ifra.Addr.Addr = d.Conf4.Addr
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFADDR", errno)
	}

	ifra.Addr.Addr = d.Conf4.Mask
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFNETMASK", errno)
	}

	return nil
}

func (d *Device) setInterfaceAddress6(addr, mask, gateway string) error {
	d.Conf6.Addr = Parse6(addr)
	d.Conf6.Mask = Parse6(mask)
	d.Conf6.Gateway = Parse6(gateway)

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	interf, err := net.InterfaceByName(d.Name)
	if err != nil {
		return err
	}

	type in6_ifreqaddr struct {
		Addr      unix.RawSockaddrInet6
		Prefixlen uint32
		IfIndex   uint
	}

	ones, _ := net.IPMask(d.Conf6.Mask[:]).Size()

	ifra := in6_ifreqaddr{
		Addr: unix.RawSockaddrInet6{
			Family: unix.AF_INET6,
		},
		Prefixlen: uint32(ones),
		IfIndex:   uint(interf.Index),
	}

	ifra.Addr.Addr = d.Conf6.Addr
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFADDR", errno)
	}

	return nil
}

func (d *Device) Activate() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	type ifreqflags struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}

	ifrf := ifreqflags{}
	copy(ifrf.Name[:], []byte(d.Name))

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCGIFFLAGS", errno)
	}

	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFFLAGS", errno)
	}

	return nil
}

func (d *Device) addRouteEntry4(cidr []string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	nameBytes := [16]byte{}
	copy(nameBytes[:], []byte(d.Name))

	route := rtEntry{
		rt_dst: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   [4]byte{},
		},
		rt_gateway: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   d.Conf4.Gateway,
		},
		rt_genmask: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   [4]byte{},
		},
		rt_flags: unix.RTF_UP | unix.RTF_GATEWAY,
		rt_dev:   uintptr(unsafe.Pointer(&nameBytes)),
	}

	for _, item := range cidr {
		_, ipNet, _ := net.ParseCIDR(item)

		ip4 := ipNet.IP.To4()
		mask := net.IP(ipNet.Mask).To4()

		route.rt_dst.Addr = *(*[4]byte)(unsafe.Pointer(&ip4[0]))
		route.rt_genmask.Addr = *(*[4]byte)(unsafe.Pointer(&mask[0]))

		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCADDRT, uintptr(unsafe.Pointer(&route))); errno != 0 {
			return os.NewSyscallError("ioctl: SIOCADDRT", errno)
		}
	}

	return nil
}

func (d *Device) addRouteEntry6(cidr []string) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	interf, err := net.InterfaceByName(d.Name)
	if err != nil {
		return err
	}

	route := new(in6RTMessage)
	// route.rtmsg_metric = 1
	route.rtmsg_flags = uint32(interf.Flags) | unix.RTF_UP | unix.RTF_GATEWAY // | unix.RTF_HOST
	route.rtmsg_ifindex = interf.Index

	for _, item := range cidr {
		_, ipNet, _ := net.ParseCIDR(item)

		ip6 := ipNet.IP.To16()
		mask := net.IPMask(net.IP(ipNet.Mask).To16())

		ones, _ := mask.Size()
		route.rtmsg_dst.Addr = *(*[16]byte)(unsafe.Pointer(&ip6[0]))
		route.rtmsg_dst_len = uint16(ones)

		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCADDRT, uintptr(unsafe.Pointer(&route))); errno != 0 {
			return os.NewSyscallError("ioctl: SIOCADDRT", errno)
		}
	}

	return nil
}
