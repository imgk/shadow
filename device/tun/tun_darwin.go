// +build darwin

package tun

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const _IOC_OUT = 0x40000000
const _IOC_IN = 0x80000000
const _IOC_INOUT = _IOC_IN | _IOC_OUT

// #define	SIOCAIFADDR_IN6		_IOW('i', 26, struct in6_aliasreq) = 0x8080691a
const _SIOCAIFADDR_IN6 = _IOC_IN | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 26

// #define	SIOCPROTOATTACH_IN6	_IOWR('i', 110, struct in6_aliasreq_64)
const _SIOCPROTOATTACH_IN6 = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 110

// #define	SIOCLL_START		_IOWR('i', 130, struct in6_aliasreq)
const _SIOCLL_START = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 130

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

	var ifr [unix.IFNAMSIZ]byte
	copy(ifr[:], []byte(d.Name))

	// set IPv4 address
	fd4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd4)

	fd := uintptr(fd4)

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/sockio.h#L107
	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/net/if.h#L570-L575
	// https://man.openbsd.org/netintro.4#SIOCAIFADDR
	type aliasreq struct {
		ifra_name    [unix.IFNAMSIZ]byte
		ifra_addr    unix.RawSockaddrInet4
		ifra_dstaddr unix.RawSockaddrInet4
		ifra_mask    unix.RawSockaddrInet4
	}

	ifra4 := aliasreq{
		ifra_name: ifr,
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

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.SIOCAIFADDR), uintptr(unsafe.Pointer(&ifra4))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCAIFADDR", errno)
	}

	// attach link-local address
	fd6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd6)

	fd = uintptr(fd6)

	// SIOCAIFADDR_IN6
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

	// Attach link-local address
	ifra6 := in6_aliasreq{
		ifra_name: ifr,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(_SIOCPROTOATTACH_IN6), uintptr(unsafe.Pointer(&ifra6))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCPROTOATTACH_IN6", errno)
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(_SIOCLL_START), uintptr(unsafe.Pointer(&ifra6))); errno != 0 {
		return os.NewSyscallError("ioctl: SIOCLL_START", errno)
	}

	return nil
}

// https://github.com/apple/darwin-xnu/blob/master/bsd/net/route.h#L343-L356
type rtMetrics struct {
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

type rtMessageHeader struct {
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
	rtm_rmx     rtMetrics
}

func (d *Device) AddRouteEntry(cidr []string) error {
	return d.modifyRouteTable(cidr, 1) /* RTM_ADD 0x1 */
}

func (d *Device) DelRouteEntry(cidr []string) error {
	return d.modifyRouteTable(cidr, 2) /* RTM_DELETE 0x02 */
}

func (d *Device) modifyRouteTable(cidr []string, cmd byte) error {
	// https://opensource.apple.com/source/network_cmds/network_cmds-596/route.tproj/route.c.auto.html
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("new socket error:%w", err)
	}
	defer unix.Close(fd)

	Roundup := func(a uintptr) uintptr {
		if a > 0 {
			return 1 + ((a - 1) | (unsafe.Sizeof(uint32(0)) - 1))
		}

		return unsafe.Sizeof(uint32(0))
	}

	l := Roundup(unix.SizeofSockaddrInet4)

	type message struct {
		hdr rtMessageHeader
		bb  [512]byte
	}

	interf, err := net.InterfaceByName(d.Name)
	if err != nil {
		return err
	}

	// https://gitlab.run.montefiore.ulg.ac.be/sdn-pp/fastclick/blob/master/elements/userlevel/kerneltun.cc#L292-334
	msgSlice := make([]byte, unsafe.Sizeof(message{}))

	msg := (*message)(unsafe.Pointer(&msgSlice[0]))
	msg.hdr.rtm_msglen = uint16(unsafe.Sizeof(rtMessageHeader{}) + l + l + l)
	msg.hdr.rtm_version = 5 /* RTM_VERSION 5 */
	msg.hdr.rtm_type = cmd
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
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return fmt.Errorf("cidr %v error: %w", item, err)
		}

		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			return fmt.Errorf("not ipv4 address")
		}
		mask := ipNet.Mask

		msg_dest.Addr = [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
		msg_mask.Addr = [4]byte{mask[0], mask[1], mask[2], mask[3]}

		if _, err := unix.Write(fd, msgSlice[:msg.hdr.rtm_msglen]); err != nil {
			return fmt.Errorf("write to socket error: %w", err)
		}

		msg.hdr.rtm_seq++
	}

	return nil
}
