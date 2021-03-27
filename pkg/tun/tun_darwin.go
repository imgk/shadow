// +build darwin

package tun

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"golang.zx2c4.com/wireguard/tun"
)

// NewDeviceFromFile is ...
func NewDeviceFromFile(file *os.File, mtu int) (dev *Device, err error) {
	dev = &Device{}
	device, err := tun.CreateTUNFromFile(file, 0 /* mtu */)
	if err != nil {
		return
	}
	dev.NativeTun = device.(*tun.NativeTun)
	if dev.Name, err = dev.NativeTun.Name(); err != nil {
		return
	}
	dev.MTU = mtu
	return
}

// setInterfaceAddress4 is ...
func (d *Device) setInterfaceAddress4(addr, mask, gateway string) (err error) {
	d.Conf4.Addr = parse4(addr)
	d.Conf4.Mask = parse4(mask)
	d.Conf4.Gateway = parse4(gateway)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/sockio.h#L107
	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/net/if.h#L570-L575
	// https://man.openbsd.org/netintro.4#SIOCAIFADDR
	type aliasreq struct {
		ifra_name    [unix.IFNAMSIZ]byte
		ifra_addr    unix.RawSockaddrInet4
		ifra_dstaddr unix.RawSockaddrInet4
		ifra_mask    unix.RawSockaddrInet4
	}

	ifra := aliasreq{
		ifra_addr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   d.Conf4.Addr,
		},
		ifra_dstaddr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   d.Conf4.Gateway,
		},
		ifra_mask: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   d.Conf4.Mask,
		},
	}
	copy(ifra.ifra_name[:], d.Name[:])

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCAIFADDR), uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCAIFADDR", errno)
	}

	return nil
}

// setInterfaceAddress6 is ...
func (d *Device) setInterfaceAddress6(addr, mask, gateway string) (err error) {
	d.Conf6.Addr = parse6(addr)
	d.Conf6.Mask = parse6(mask)
	d.Conf6.Gateway = parse6(gateway)

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_SETFD), uintptr(unix.FD_CLOEXEC)); errno != 0 {
		return os.NewSyscallError("fcntl: F_SETFD, FD_CLOEXEC", errno)
	}

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h#L114-L119
	// https://opensource.apple.com/source/network_cmds/network_cmds-543.260.3/
	type in6_addrlifetime struct {
		ia6t_expire    uint64
		ia6t_preferred uint64
		ia6t_vltime    uint32
		ia6t_pltime    uint32
	}

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h#L336-L343
	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6.h#L174-L181
	type in6_aliasreq struct {
		ifra_name       [unix.IFNAMSIZ]byte
		ifra_addr       unix.RawSockaddrInet6
		ifra_dstaddr    unix.RawSockaddrInet6
		ifra_prefixmask unix.RawSockaddrInet6
		ifra_flags      int32
		ifra_lifetime   in6_addrlifetime
	}

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/nd6.h#L469
	const ND6_INFINITE_LIFETIME = 0xffffffff

	in6_ifra := in6_aliasreq{
		ifra_addr: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   d.Conf6.Addr,
		},
		ifra_prefixmask: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   d.Conf6.Mask,
		},
		ifra_lifetime: in6_addrlifetime{
			ia6t_expire:    ND6_INFINITE_LIFETIME,
			ia6t_preferred: ND6_INFINITE_LIFETIME,
			ia6t_vltime:    ND6_INFINITE_LIFETIME,
			ia6t_pltime:    ND6_INFINITE_LIFETIME,
		},
	}
	copy(in6_ifra.ifra_name[:], d.Name[:])

	const (
		IOC_OUT   = 0x40000000
		IOC_IN    = 0x80000000
		IOC_INOUT = IOC_IN | IOC_OUT
	)

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h
	// #define SIOCAIFADDR_IN6	   _IOW('i', 26, struct in6_aliasreq)
	const SIOCAIFADDR_IN6 = IOC_IN | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 26

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(SIOCAIFADDR_IN6), uintptr(unsafe.Pointer(&in6_ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCAIFADDR_IN6", errno)
	}

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h#L319-L334
	type in6_ifreq struct {
		ifra_name [unix.IFNAMSIZ]byte
		_         [unix.SizeofSockaddrInet6]byte
	}

	in6_ifr := in6_ifreq{}
	copy(in6_ifr.ifra_name[:], d.Name[:])

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h
	// #define SIOCPROTOATTACH_IN6 _IOWR('i', 110, struct in6_aliasreq_64)
	const SIOCPROTOATTACH_IN6 = IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 110

	// Attach link-local address
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(SIOCPROTOATTACH_IN6), uintptr(unsafe.Pointer(&in6_ifr))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCPROTOATTACH_IN6", errno)
	}

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h
	// #define SIOCLL_START        _IOWR('i', 130, struct in6_aliasreq)
	const SIOCLL_START = IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 130

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(SIOCLL_START), uintptr(unsafe.Pointer(&in6_ifr))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCLL_START", errno)
	}

	return nil
}

// Activate is ...
func (d *Device) Activate() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// ifreq_flags is ...
	type ifreq_flags struct {
		Name  [16]byte
		Flags uint16
		_     [unsafe.Sizeof(unix.RawSockaddrInet4{}) - unsafe.Sizeof(uint16(0))]byte
	}

	ifrf := ifreq_flags{}
	copy(ifrf.Name[:], d.Name[:])

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCGIFFLAGS", errno)
	}

	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCSIFFLAGS", errno)
	}

	return nil
}

func roundup(a uintptr) uintptr {
	if a > 0 {
		return 1 + ((a - 1) | (unsafe.Sizeof(uint32(0)) - 1))
	}

	return unsafe.Sizeof(uint32(0))
}

// addRouteEntry4 is ...
func (d *Device) addRouteEntry4(cidr []string) error {
	// https://opensource.apple.com/source/network_cmds/network_cmds-596/route.tproj/route.c.auto.html
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	l := roundup(unix.SizeofSockaddrInet4)

	type rt_message struct {
		hdr unix.RtMsghdr
		bb  [512]byte
	}

	interf, err := net.InterfaceByName(d.Name)
	if err != nil {
		return err
	}

	// https://gitlab.run.montefiore.ulg.ac.be/sdn-pp/fastclick/blob/master/elements/userlevel/kerneltun.cc#L292-334
	msgSlice := make([]byte, unsafe.Sizeof(unix.RtMsghdr{})+l+l+l)

	msg := (*rt_message)(unsafe.Pointer(&msgSlice[0]))
	msg.hdr.Msglen = uint16(unsafe.Sizeof(unix.RtMsghdr{}) + l + l + l)
	msg.hdr.Version = unix.RTM_VERSION
	msg.hdr.Type = unix.RTM_ADD
	msg.hdr.Index = uint16(interf.Index)
	msg.hdr.Flags = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC
	msg.hdr.Addrs = unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK
	msg.hdr.Pid = 0
	msg.hdr.Seq = 0
	msg.hdr.Errno = 0
	msg.hdr.Use = 0
	msg.hdr.Inits = 0

	msg_dest := (*unix.RawSockaddrInet4)(unsafe.Pointer(&msg.bb))
	msg_dest.Len = unix.SizeofSockaddrInet4
	msg_dest.Family = unix.AF_INET

	msg_gateway := (*unix.RawSockaddrInet4)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l))
	msg_gateway.Len = unix.SizeofSockaddrInet4
	msg_gateway.Family = unix.AF_INET
	msg_gateway.Addr = d.Conf4.Gateway

	msg_mask := (*unix.RawSockaddrInet4)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l + l))
	msg_mask.Len = unix.SizeofSockaddrInet4
	msg_mask.Family = unix.AF_INET

	for _, item := range cidr {
		_, ipNet, _ := net.ParseCIDR(item)

		ipv4 := ipNet.IP.To4()
		mask := net.IP(ipNet.Mask).To4()

		msg_dest.Addr = *(*[4]byte)(unsafe.Pointer(&ipv4[0]))
		msg_mask.Addr = *(*[4]byte)(unsafe.Pointer(&mask[0]))

		if _, err := unix.Write(fd, msgSlice[:msg.hdr.Msglen]); err != nil {
			return fmt.Errorf("write to socket error: %w", err)
		}

		msg.hdr.Seq++
	}

	return nil
}

// addRouteEntry6 is ...
func (d *Device) addRouteEntry6(cidr []string) error {
	// https://opensource.apple.com/source/network_cmds/network_cmds-596/route.tproj/route.c.auto.html
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	l := roundup(unix.SizeofSockaddrInet6)

	type rt_message struct {
		hdr unix.RtMsghdr
		bb  [512]byte
	}

	interf, err := net.InterfaceByName(d.Name)
	if err != nil {
		return err
	}

	// https://gitlab.run.montefiore.ulg.ac.be/sdn-pp/fastclick/blob/master/elements/userlevel/kerneltun.cc#L292-334
	msgSlice := make([]byte, unsafe.Sizeof(unix.RtMsghdr{})+l+l+l)

	msg := (*rt_message)(unsafe.Pointer(&msgSlice[0]))
	msg.hdr.Msglen = uint16(unsafe.Sizeof(unix.RtMsghdr{}) + l + l + l)
	msg.hdr.Version = unix.RTM_VERSION
	msg.hdr.Type = unix.RTM_ADD
	msg.hdr.Index = uint16(interf.Index)
	msg.hdr.Flags = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC
	msg.hdr.Addrs = unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK
	msg.hdr.Pid = 0
	msg.hdr.Seq = 0
	msg.hdr.Errno = 0
	msg.hdr.Use = 0
	msg.hdr.Inits = 0

	msg_dest := (*unix.RawSockaddrInet6)(unsafe.Pointer(&msg.bb))
	msg_dest.Len = unix.SizeofSockaddrInet6
	msg_dest.Family = unix.AF_INET6

	msg_gateway := (*unix.RawSockaddrInet6)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l))
	msg_gateway.Len = unix.SizeofSockaddrInet6
	msg_gateway.Family = unix.AF_INET6
	msg_gateway.Addr = d.Conf6.Gateway

	msg_mask := (*unix.RawSockaddrInet6)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l + l))
	msg_mask.Len = unix.SizeofSockaddrInet6
	msg_mask.Family = unix.AF_INET6

	for _, item := range cidr {
		_, ipNet, _ := net.ParseCIDR(item)

		ipv6 := ipNet.IP.To16()
		mask := net.IP(ipNet.Mask).To16()

		msg_dest.Addr = *(*[16]byte)(unsafe.Pointer(&ipv6[0]))
		msg_mask.Addr = *(*[16]byte)(unsafe.Pointer(&mask[0]))

		if _, err := unix.Write(fd, msgSlice[:msg.hdr.Msglen]); err != nil {
			return fmt.Errorf("write to socket error: %w", err)
		}

		msg.hdr.Seq++
	}

	return nil
}
