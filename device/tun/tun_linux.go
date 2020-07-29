// +build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

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

func (d *Device) AddRouteEntry(cidr []string) error {
	return d.modifyRouteTable(cidr, unix.SIOCADDRT)
}

func (d *Device) DelRouteEntry(cidr []string) error {
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
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return err
		}

		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			return fmt.Errorf("not ipv4 address: %v", item)
		}
		mask := ipNet.Mask

		route.rt_dst.Addr = [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
		route.rt_genmask.Addr = [4]byte{mask[0], mask[1], mask[2], mask[3]}

		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, cmd, uintptr(unsafe.Pointer(&route))); errno != 0 {
			return os.NewSyscallError("ioctl: SIOCADDRT/SIOCDELRT", errno)
		}
	}

	return nil
}
