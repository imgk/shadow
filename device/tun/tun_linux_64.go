// +build linux
// +build amd64 arm64

package tun

import (
	"golang.org/x/sys/unix"
)

//https://github.com/torvalds/linux/blob/master/include/uapi/linux/route.h
type rtEntry struct {
	rt_pad1    uint32
	_          uint32
	rt_dst     unix.RawSockaddrInet4
	rt_gateway unix.RawSockaddrInet4
	rt_genmask unix.RawSockaddrInet4
	rt_flags   uint16
	rt_pad2    int16
	_          uint32
	rt_pad3    uint32
	_          uint32
	rt_pad4    uintptr
	rt_metric  int16
	rt_dev     uintptr
	rt_mtu     uint32
	_          uint32
	rt_window  uint32
	_          uint32
	rt_irtt    uint16
}
