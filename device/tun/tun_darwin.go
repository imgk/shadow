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

func NewDeviceFromFile(file *os.File, mtu int) (dev *Device, err error) {
	dev = &Device{}
	device, err := tun.CreateTUNFromFile(file, mtu)
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

const (
	_RTM_ADD     = 1
	_RTM_DELETE  = 2
	_RTM_VERSION = 5

	_IOC_OUT   = 0x40000000
	_IOC_IN    = 0x80000000
	_IOC_INOUT = _IOC_IN | _IOC_OUT

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h
	// #define SIOCAIFADDR_IN6	   _IOW('i', 26, struct in6_aliasreq)
	// #define SIOCPROTOATTACH_IN6 _IOWR('i', 110, struct in6_aliasreq_64)
	// #define SIOCLL_START        _IOWR('i', 130, struct in6_aliasreq)
	_SIOCAIFADDR_IN6     = _IOC_IN | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 26
	_SIOCPROTOATTACH_IN6 = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 110
	_SIOCLL_START        = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 130

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/nd6.h#L469
	_ND6_INFINITE_LIFETIME = 0xffffffff
)

func (d *Device) setInterfaceAddress4(addr, mask, gateway string) (err error) {
	d.Conf4.Addr = Parse4(addr)
	d.Conf4.Mask = Parse4(mask)
	d.Conf4.Gateway = Parse4(gateway)

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
	copy(ifra.ifra_name[:], []byte(d.Name))

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCAIFADDR), uintptr(unsafe.Pointer(&ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCAIFADDR", errno)
	}

	return nil
}

func (d *Device) setInterfaceAddress6(addr, mask, gateway string) (err error) {
	d.Conf6.Addr = Parse6(addr)
	d.Conf6.Mask = Parse6(mask)
	d.Conf6.Gateway = Parse6(gateway)

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
			ia6t_expire:    _ND6_INFINITE_LIFETIME,
			ia6t_preferred: _ND6_INFINITE_LIFETIME,
			ia6t_vltime:    _ND6_INFINITE_LIFETIME,
			ia6t_pltime:    _ND6_INFINITE_LIFETIME,
		},
	}
	copy(in6_ifra.ifra_name[:], []byte(d.Name))

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(_SIOCAIFADDR_IN6), uintptr(unsafe.Pointer(&in6_ifra))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCAIFADDR_IN6", errno)
	}

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h#L319-L334
	type in6_ifreq struct {
		ifra_name [unix.IFNAMSIZ]byte
		_         [unix.SizeofSockaddrInet6]byte
	}

	in6_ifr := in6_ifreq{}
	copy(in6_ifr.ifra_name[:], []byte(d.Name))

	// Attach link-local address
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(_SIOCPROTOATTACH_IN6), uintptr(unsafe.Pointer(&in6_ifr))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCPROTOATTACH_IN6", errno)
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(_SIOCLL_START), uintptr(unsafe.Pointer(&in6_ifr))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCLL_START", errno)
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
		_     [unsafe.Sizeof(unix.RawSockaddrInet4{}) - unsafe.Sizeof(uint16(0))]byte
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

// https://github.com/apple/darwin-xnu/blob/master/bsd/net/route.h#L75-L88
type rt_metrics struct {
	rmx_locks    uint32
	rmx_mtu      uint32
	rmx_hopcount uint32
	rmx_expire   int32
	rmx_recvpipe uint32
	rmx_sendpipe uint32
	rmx_ssthresh uint32
	rmx_rtt      uint32
	rmx_rttvar   uint32
	rmx_pksent   uint32
	rmx_state    uint32
	rmx_filler   [3]uint32
}

// https://github.com/apple/darwin-xnu/blob/master/bsd/net/route.h#L343-L356
type rt_msghdr struct {
	rtm_msglen  uint16
	rtm_version byte
	rtm_type    byte
	rtm_index   uint16
	rtm_flags   int32
	rtm_addrs   int32
	rtm_pid     uint32
	rtm_seq     int32
	rtm_errno   int32
	rtm_use     int32
	rtm_inits   uint32
	rtm_rmx     rt_metrics
}

func roundup(a uintptr) uintptr {
	if a > 0 {
		return 1 + ((a - 1) | (unsafe.Sizeof(uint32(0)) - 1))
	}

	return unsafe.Sizeof(uint32(0))
}

func (d *Device) addRouteEntry4(cidr []string) error {
	// https://opensource.apple.com/source/network_cmds/network_cmds-596/route.tproj/route.c.auto.html
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	l := roundup(unix.SizeofSockaddrInet4)

	type rt_message struct {
		hdr rt_msghdr
		bb  [512]byte
	}

	interf, err := net.InterfaceByName(d.Name)
	if err != nil {
		return err
	}

	// https://gitlab.run.montefiore.ulg.ac.be/sdn-pp/fastclick/blob/master/elements/userlevel/kerneltun.cc#L292-334
	msgSlice := make([]byte, unsafe.Sizeof(rt_msghdr{})+l+l+l)

	msg := (*rt_message)(unsafe.Pointer(&msgSlice[0]))
	msg.hdr.rtm_msglen = uint16(unsafe.Sizeof(rt_msghdr{}) + l + l + l)
	msg.hdr.rtm_version = _RTM_VERSION
	msg.hdr.rtm_type = _RTM_ADD
	msg.hdr.rtm_index = uint16(interf.Index)
	msg.hdr.rtm_flags = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC
	msg.hdr.rtm_addrs = unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK
	msg.hdr.rtm_pid = 0
	msg.hdr.rtm_seq = 0
	msg.hdr.rtm_errno = 0
	msg.hdr.rtm_use = 0
	msg.hdr.rtm_inits = 0

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

		ip4 := ipNet.IP.To4()
		mask := net.IP(ipNet.Mask).To4()

		msg_dest.Addr = *(*[4]byte)(unsafe.Pointer(&ip4[0]))
		msg_mask.Addr = *(*[4]byte)(unsafe.Pointer(&mask[0]))

		if _, err := unix.Write(fd, msgSlice[:msg.hdr.rtm_msglen]); err != nil {
			return fmt.Errorf("write to socket error: %w", err)
		}

		msg.hdr.rtm_seq++
	}

	return nil
}

func (d *Device) addRouteEntry6(cidr []string) error {
	// https://opensource.apple.com/source/network_cmds/network_cmds-596/route.tproj/route.c.auto.html
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	l := roundup(unix.SizeofSockaddrInet6)
	n := roundup(unix.SizeofSockaddrDatalink)

	type rt_message struct {
		hdr rt_msghdr
		bb  [512]byte
	}

	interf, err := net.InterfaceByName(d.Name)
	if err != nil {
		return err
	}

	// https://gitlab.run.montefiore.ulg.ac.be/sdn-pp/fastclick/blob/master/elements/userlevel/kerneltun.cc#L292-334
	msgSlice := make([]byte, unsafe.Sizeof(rt_msghdr{})+l+n+l)

	msg := (*rt_message)(unsafe.Pointer(&msgSlice[0]))
	msg.hdr.rtm_msglen = uint16(unsafe.Sizeof(rt_msghdr{}) + l + n + l)
	msg.hdr.rtm_version = _RTM_VERSION
	msg.hdr.rtm_type = _RTM_ADD
	msg.hdr.rtm_index = uint16(interf.Index)
	msg.hdr.rtm_flags = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC
	msg.hdr.rtm_addrs = unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK
	msg.hdr.rtm_pid = 0
	msg.hdr.rtm_seq = 0
	msg.hdr.rtm_errno = 0
	msg.hdr.rtm_use = 0
	msg.hdr.rtm_inits = 0

	msg_dest := (*unix.RawSockaddrInet6)(unsafe.Pointer(&msg.bb))
	msg_dest.Len = unix.SizeofSockaddrInet6
	msg_dest.Family = unix.AF_INET6

	msg_gateway := (*unix.RawSockaddrDatalink)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l))
	msg_gateway.Len = unix.SizeofSockaddrDatalink
	msg_gateway.Family = unix.AF_LINK
	msg_gateway.Index = uint16(interf.Index)

	msg_mask := (*unix.RawSockaddrInet6)(unsafe.Pointer(uintptr(unsafe.Pointer(&msg.bb)) + l + n))
	msg_mask.Len = unix.SizeofSockaddrInet6
	msg_mask.Family = unix.AF_INET6

	for _, item := range cidr {
		_, ipNet, _ := net.ParseCIDR(item)

		ip6 := ipNet.IP.To16()
		mask := net.IP(ipNet.Mask).To16()

		msg_dest.Addr = *(*[16]byte)(unsafe.Pointer(&ip6[0]))
		msg_mask.Addr = *(*[16]byte)(unsafe.Pointer(&mask[0]))

		if _, err := unix.Write(fd, msgSlice[:msg.hdr.rtm_msglen]); err != nil {
			return fmt.Errorf("write to socket error: %w", err)
		}

		msg.hdr.rtm_seq++
	}

	return nil
}
