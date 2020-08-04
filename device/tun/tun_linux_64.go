// +build linux
// +build amd64 arm64

package tun

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/route.h#L31-L48
type rtentry struct {
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

// https://github.com/torvalds/linux/blob/6f0d349d922ba44e4348a17a78ea51b7135965b1/include/uapi/linux/ipv6_route.h#L43-L54
type in6_rtmsg struct {
	rtmsg_dst     in6_addr
	rtmsg_src     in6_addr
	rtmsg_gateway in6_addr
	rtmsg_type    uint32
	rtmsg_dst_len uint16
	rtmsg_src_len uint16
	rtmsg_metric  uint32
	_             uint32
	rtmsg_info    uint32
	_             uint32
	rtmsg_flags   uint32
	rtmsg_ifindex int32
}
