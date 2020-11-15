// +build linux

package tun

import (
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"golang.zx2c4.com/wireguard/tun"
)

func NewUnmonitoredDeviceFromFD(fd int, mtu int) (dev *Device, err error) {
	dev = &Device{}
	device, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		return
	}
	dev.NativeTun = device.(*tun.NativeTun)
	if dev.Name, err = dev.NativeTun.Name(); err != nil {
		return
	}
	dev.MTU = mtu
	dev.buf = make([]byte, 4+dev.MTU)
	dev.buff = make([]byte, 4+dev.MTU)
	return
}

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

	type ifreq_addr struct {
		ifr_name [unix.IFNAMSIZ]byte
		ifr_addr unix.RawSockaddrInet4
		_        [8]byte
	}

	ifra := ifreq_addr{
		ifr_addr: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
		},
	}
	copy(ifra.ifr_name[:], []byte(d.Name))

	ifra.ifr_addr.Addr = d.Conf4.Addr
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFADDR", errno)
	}

	ifra.ifr_addr.Addr = d.Conf4.Mask
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFNETMASK", errno)
	}

	return nil
}

type in6_addr struct {
	addr [16]byte
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

	type ifreq_ifindex struct {
		ifr_name    [unix.IFNAMSIZ]byte
		ifr_ifindex int32
		_           [20]byte
	}

	ifrf := ifreq_ifindex{}
	copy(ifrf.ifr_name[:], []byte(d.Name))

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFINDEX, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCGIFINDEX", errno)
	}

	type in6_ifreq_addr struct {
		ifr6_addr      in6_addr
		ifr6_prefixlen uint32
		ifr6_ifindex   int32
	}

	ones, _ := net.IPMask(d.Conf6.Mask[:]).Size()

	ifra := in6_ifreq_addr{
		ifr6_prefixlen: uint32(ones),
		ifr6_ifindex:   ifrf.ifr_ifindex,
	}

	ifra.ifr6_addr.addr = d.Conf6.Addr
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

	type ifreq_flags struct {
		ifr_name  [unix.IFNAMSIZ]byte
		ifr_flags uint16
		_         [22]byte
	}

	ifrf := ifreq_flags{}
	copy(ifrf.ifr_name[:], []byte(d.Name))

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCGIFFLAGS", errno)
	}

	ifrf.ifr_flags = ifrf.ifr_flags | unix.IFF_UP | unix.IFF_RUNNING
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

	route := rtentry{
		rt_dst: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
		},
		rt_gateway: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   d.Conf4.Gateway,
		},
		rt_genmask: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
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

	type ifreq_ifindex struct {
		ifr_name    [unix.IFNAMSIZ]byte
		ifr_ifindex int32
		_           [20]byte
	}

	ifrf := ifreq_ifindex{}
	copy(ifrf.ifr_name[:], []byte(d.Name))

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFINDEX, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCGIFINDEX", errno)
	}

	route := in6_rtmsg{
		rtmsg_metric:  1,
		rtmsg_ifindex: ifrf.ifr_ifindex,
	}

	for _, item := range cidr {
		_, ipNet, _ := net.ParseCIDR(item)

		ip6 := ipNet.IP.To16()
		mask := net.IP(ipNet.Mask).To16()

		ones, _ := net.IPMask(mask).Size()
		route.rtmsg_dst.addr = *(*[16]byte)(unsafe.Pointer(&ip6[0]))
		route.rtmsg_dst_len = uint16(ones)
		route.rtmsg_flags = unix.RTF_UP
		if ones == 128 {
			route.rtmsg_flags |= unix.RTF_HOST
		}

		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCADDRT, uintptr(unsafe.Pointer(&route))); errno != 0 {
			return os.NewSyscallError("ioctl: SIOCADDRT", errno)
		}
	}

	return nil
}
