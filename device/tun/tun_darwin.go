// +build darwin

package tun

import (
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

const utunControlName = "com.apple.net.utun_control"
const _IOC_OUT = 0x40000000
const _IOC_IN = 0x80000000
const _IOC_INOUT = _IOC_IN | _IOC_OUT

const _SYSPROTO_CONTROL = 2 /* #define SYSPROTO_CONTROL 2 */
const _UTUN_OPT_IFNAME  = 2 /* #define UTUN_OPT_IFNAME 2 */

// _CTLIOCGINFO value derived from /usr/include/sys/{kern_control,ioccom}.h
// https://github.com/apple/darwin-xnu/blob/master/bsd/sys/ioccom.h

// _CTLIOCGINFO value derived from /usr/include/sys/{kern_control,ioccom}.h
const _CTLIOCGINFO = (0x40000000 | 0x80000000) | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3

// #define	SIOCAIFADDR_IN6		_IOW('i', 26, struct in6_aliasreq) = 0x8080691a
const _SIOCAIFADDR_IN6 = _IOC_IN | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 26

// #define	SIOCPROTOATTACH_IN6	_IOWR('i', 110, struct in6_aliasreq_64)
const _SIOCPROTOATTACH_IN6 = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 110

// #define	SIOCLL_START		_IOWR('i', 130, struct in6_aliasreq)
const _SIOCLL_START = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 130

// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/nd6.h#L469
const ND6_INFINITE_LIFETIME = 0xffffffff

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

	ctlInfo := struct {
		ctlID   uint32
		ctlName [96]byte
	}{}

	copy(ctlInfo.ctlName[:], []byte(utunControlName))

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(_CTLIOCGINFO), uintptr(unsafe.Pointer(&ctlInfo))); errno != 0 {
		return nil, os.NewSyscallError("ioctl: _CTLIOCGINFO", errno)
	}

	sc := sockaddrCtl{
		scLen:     uint8(sockaddrCtlSize),
		scFamily:  unix.AF_SYSTEM,
		ssSysaddr: 2,
		scID:      ctlInfo.ctlID,
		scUnit:    uint32(ifIndex) + 1,
	}

	if _, _, errno := unix.RawSyscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sc)), uintptr(sockaddrCtlSize)); errno != 0 {
		return nil, fmt.Errorf("SYS_CONNECT: %v", errno)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}

	dev := &Device{
		File:   os.NewFile(uintptr(fd), name),
		active: make(chan struct{}),
		rBuf:   make([]byte, 4+1500),
		wBuf:   make([]byte, 4+1500),
	}

	if name, err = dev.GetTunName(); err != nil {
		return nil, err
	}

	dev.Name = name

	return dev, nil
}

func NewDeviceFromFd(fd uint) (*Device, error) {
	ifName := struct {
		name [16]byte
	}{}
	ifNameSize := uintptr(16)

	if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), _SYSPROTO_CONTROL, _UTUN_OPT_IFNAME, uintptr(unsafe.Pointer(&ifName)), uintptr(unsafe.Pointer(&ifNameSize)), 0); errno != 0 {
		return nil, os.NewSyscallError("SYS_GETSOCKOPT", errno)
	}

	name := string(ifName.name[:ifNameSize-1])

	dev := &Device{
		File:   os.NewFile(uintptr(fd), name),
		Name:   name,
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
			Addr:   d.Conf4.Addr,
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

type rtMetrics struct {
	rmx_locks     uint32
	rmx_mtu       uint32
	rmx_hopcount  uint32
	rmx_expire    int32
	rmx_recvpipe  uint32
	rmx_sendpipe  uint32
	rmx_ssthresh  uint32
	rmx_rtt       uint32
	rmx_rttvar    uint32
	rmx_pksent    uint32
	rmx_state     uint32
	rmx_filler    [3]uint32
}

type rtMessageHeader struct {
	rtm_msglen  uint16
	rtm_version byte
	rtm_type    byte
	rtm_index   uint16
	rtm_flags   int	   
	rtm_addrs   int	   
	rtm_pid     uint
	rtm_seq     int	   
	rtm_errno   int	   
	rtm_use     int	   
	rtm_inits   uint32
	rtm_rmx     rtMetrics
}

func (d *Device) AddRoute(cidr []string) error {
	return d.modifyRouteTable(cidr, 1) /* RTM_ADD 0x1 */
}

func (d *Device) DelRoute(cidr []string) error {
	return d.modifyRouteTable(cidr, 2) /* RTM_DELETE 0x02 */
}

func (d *Device) modifyRouteTable(cidr []string, cmd byte) error {
	// https://pdos.csail.mit.edu/pipermail/click/2009-December/008473.html
	// https://opensource.apple.com/source/network_cmds/network_cmds-596/route.tproj/route.c.auto.html
	// https://github.com/apple/darwin-xnu/blob/master/bsd/net/route.h
	// https://github.com/apple/darwin-xnu/blob/master/bsd/net/if_dl.h
	// https://github.com/apple/darwin-xnu/blob/master/bsd/netinet/in.h
	// https://github.com/apple/darwin-xnu/blob/master/bsd/sys/socket.h
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return fmt.Errorf("new socket error:%w", err)
	}
	defer unix.Close(fd)

	type message struct {
		hdr     rtMessageHeader
		dest    unix.RawSockaddrInet4
		gateway unix.RawSockaddrInet4
		mask    unix.RawSockaddrInet4
	}

	msgSlice := make([]byte, unsafe.Sizeof(message{}))

	msg := (*message)(unsafe.Pointer(&msgSlice[0]))
	msg.hdr.rtm_msglen  = uint16(unsafe.Sizeof(message{}))
	msg.hdr.rtm_version = 5 /* RTM_VERSION 5 */
	msg.hdr.rtm_type    = cmd
	msg.hdr.rtm_index   = 0
	msg.hdr.rtm_pid     = 0
	msg.hdr.rtm_addrs   = unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK
	msg.hdr.rtm_seq     = 0
	msg.hdr.rtm_errno   = 0
	msg.hdr.rtm_flags   = unix.RTF_UP | unix.RTF_GATEWAY

	msg.dest = unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   [4]byte{},
	}

	msg.gateway = unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   d.Conf4.Gateway,
	}

	msg.mask = unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   [4]byte{},
	}

	for i, item := range cidr {
		msg.hdr.rtm_seq = i

		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return fmt.Errorf("cidr %v error: %w", item, err)
		}

		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			return fmt.Errorf("not ipv4 address")
		}
		mask := ipNet.Mask

		msg.dest.Addr = [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
		msg.mask.Addr = [4]byte{mask[0], mask[1], mask[2], mask[3]}

		if _, err := unix.Write(fd, msgSlice); err != nil {
			return fmt.Errorf("write to socket error: %w", err)
		}
	}

	return nil
}

func (d *Device) GetTunName() (string, error) {
	conn, err := d.File.SyscallConn()
	if err != nil {
		return "", err
	}

	ifName := struct {
		name [16]byte
	}{}
	ifNameSize := uintptr(16)

	var errno unix.Errno
	fn := func(fd uintptr) {
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, _SYSPROTO_CONTROL, _UTUN_OPT_IFNAME, uintptr(unsafe.Pointer(&ifName)), uintptr(unsafe.Pointer(&ifNameSize)), 0)
	}

	if err := conn.Control(fn); err != nil {
		return "", fmt.Errorf("sysconn control func error: %w", err)
	}
	if errno != 0 {
		return "", os.NewSyscallError("SYS_GETSOCKOPT", errno)
	}

	return string(ifName.name[:ifNameSize-1]), nil
}

func (d *Device) Write(b []byte) (int, error) {
	n := copy(d.wBuf[4:], b)

	switch d.wBuf[4] >> 4 {
	case ipv6.Version:
		d.wBuf[3] = unix.AF_INET6
	case ipv4.Version:
		d.wBuf[3] = unix.AF_INET
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
				d.wBuf[3] = unix.AF_INET6
			case ipv4.Version:
				d.wBuf[3] = unix.AF_INET
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
