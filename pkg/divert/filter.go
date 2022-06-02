//go:build windows

package divert

import (
	"net"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/imgk/shadow/pkg/divert/filter"
)

const (
	// ProtoTCP is ...
	ProtoTCP = 6
	// ProtoUDP is ...
	ProtoUDP = 17
)

const (
	// FIN is ...
	FIN = 1 << 0
	// SYN is ...
	SYN = 1 << 1
)

// PacketFilter is ...
type PacketFilter struct {
	// AppFilter is ...
	AppFilter *filter.AppFilter
	// IPFilter is ...
	IPFilter *filter.IPFilter
	// Hijack is ...
	Hijack bool

	// TCP4Table is ...
	TCP4Table []uint8
	// UDP4Table is ...
	UDP4Table []uint8
	// TCP6Table is ...
	TCP6Table []uint8
	// UDP6Table is ...
	UDP6Table []uint8

	buff []byte
}

// CheckIPv4 is ...
func (d *PacketFilter) CheckIPv4(b []byte) bool {
	switch b[9] {
	case ProtoTCP:
		p := uint32(b[ipv4.HeaderLen])<<8 | uint32(b[ipv4.HeaderLen+1])
		switch d.TCP4Table[p] {
		case 0:
			if b[ipv4.HeaderLen+13]&SYN != SYN {
				d.TCP4Table[p] = 1
				return false
			}

			if d.IPFilter.Lookup(net.IP(b[16:20])) {
				d.TCP4Table[p] = 2
				return true
			}

			if d.CheckTCP4ByPID(b) {
				d.TCP4Table[p] = 2
				return true
			}

			d.TCP4Table[p] = 1
			return false
		case 1:
			if b[ipv4.HeaderLen+13]&FIN == FIN {
				d.TCP4Table[p] = 0
			}

			return false
		case 2:
			if b[ipv4.HeaderLen+13]&FIN == FIN {
				d.TCP4Table[p] = 0
			}

			return true
		}
	case ProtoUDP:
		p := uint32(b[ipv4.HeaderLen])<<8 | uint32(b[ipv4.HeaderLen+1])

		switch d.UDP4Table[p] {
		case 0:
			fn := func() { d.UDP4Table[p] = 0 }

			if d.IPFilter.Lookup(net.IP(b[16:20])) {
				d.UDP4Table[p] = 2
				time.AfterFunc(time.Minute, fn)
				return true
			}

			if d.CheckUDP4ByPID(b) {
				d.UDP4Table[p] = 2
				time.AfterFunc(time.Minute, fn)
				return true
			}

			if (uint32(b[ipv4.HeaderLen+2])<<8|uint32(b[ipv4.HeaderLen+3])) == 53 && d.Hijack {
				return true
			}

			d.UDP4Table[p] = 1
			time.AfterFunc(time.Minute, fn)

			return false
		case 1:
			return false
		case 2:
			return true
		}
	default:
		return d.IPFilter.Lookup(net.IP(b[16:20]))
	}

	return false
}

// CheckTCP4ByPID is ...
func (d *PacketFilter) CheckTCP4ByPID(b []byte) bool {
	if d.AppFilter == nil {
		return false
	}

	rt, err := filter.GetTCPTable(d.buff)
	if err != nil {
		return false
	}

	p := uint32(b[ipv4.HeaderLen]) | uint32(b[ipv4.HeaderLen+1])<<8

	for i := range rt {
		if rt[i].LocalPort == p {
			if *(*uint32)(unsafe.Pointer(&b[12])) == rt[i].LocalAddr {
				return d.AppFilter.Lookup(rt[i].OwningPid)
			}
		}
	}

	return false
}

// CheckUDP4ByPID is ...
func (d *PacketFilter) CheckUDP4ByPID(b []byte) bool {
	if d.AppFilter == nil {
		return false
	}

	rt, err := filter.GetUDPTable(d.buff)
	if err != nil {
		return false
	}

	p := uint32(b[ipv4.HeaderLen]) | uint32(b[ipv4.HeaderLen+1])<<8

	for i := range rt {
		if rt[i].LocalPort == p {
			if 0 == rt[i].LocalAddr || *(*uint32)(unsafe.Pointer(&b[12])) == rt[i].LocalAddr {
				return d.AppFilter.Lookup(rt[i].OwningPid)
			}
		}
	}

	return false
}

// CheckIPv6 is ...
func (d *PacketFilter) CheckIPv6(b []byte) bool {
	switch b[6] {
	case ProtoTCP:
		p := uint32(b[ipv6.HeaderLen])<<8 | uint32(b[ipv6.HeaderLen+1])
		switch d.TCP6Table[p] {
		case 0:
			if b[ipv6.HeaderLen+13]&SYN != SYN {
				d.TCP6Table[p] = 1
				return false
			}

			if d.IPFilter.Lookup(net.IP(b[24:40])) {
				d.TCP6Table[p] = 2
				return true
			}

			if d.CheckTCP6ByPID(b) {
				d.TCP6Table[p] = 2
				return true
			}

			d.TCP6Table[p] = 1
			return false
		case 1:
			if b[ipv6.HeaderLen+13]&FIN == FIN {
				d.TCP6Table[p] = 0
			}

			return false
		case 2:
			if b[ipv6.HeaderLen+13]&FIN == FIN {
				d.TCP6Table[p] = 0
			}

			return true
		}
	case ProtoUDP:
		p := uint32(b[ipv6.HeaderLen])<<8 | uint32(b[ipv6.HeaderLen+1])

		switch d.UDP6Table[p] {
		case 0:
			fn := func() { d.UDP6Table[p] = 0 }

			if d.IPFilter.Lookup(net.IP(b[24:40])) {
				d.UDP6Table[p] = 2
				time.AfterFunc(time.Minute, fn)
				return true
			}

			if d.CheckUDP6ByPID(b) {
				d.UDP6Table[p] = 2
				time.AfterFunc(time.Minute, fn)
				return true
			}

			if (uint32(b[ipv6.HeaderLen+2])<<8|uint32(b[ipv6.HeaderLen+3])) == 53 && d.Hijack {
				return true
			}

			d.UDP6Table[p] = 1
			time.AfterFunc(time.Minute, fn)
			return false
		case 1:
			return false
		case 2:
			return true
		}
	default:
		return d.IPFilter.Lookup(net.IP(b[24:40]))
	}

	return false
}

// CheckTCP6ByPID is ...
func (d *PacketFilter) CheckTCP6ByPID(b []byte) bool {
	if d.AppFilter == nil {
		return false
	}

	rt, err := filter.GetTCP6Table(d.buff)
	if err != nil {
		return false
	}

	p := uint32(b[ipv6.HeaderLen]) | uint32(b[ipv6.HeaderLen+1])<<8
	a := *(*[4]uint32)(unsafe.Pointer(&b[8]))

	for i := range rt {
		if rt[i].LocalPort == p {
			if a[0] == rt[i].LocalAddr[0] && a[1] == rt[i].LocalAddr[1] && a[2] == rt[i].LocalAddr[2] && a[3] == rt[i].LocalAddr[3] {
				return d.AppFilter.Lookup(rt[i].OwningPid)
			}
		}
	}

	return false
}

// CheckUDP6ByPID is ...
func (d *PacketFilter) CheckUDP6ByPID(b []byte) bool {
	if d.AppFilter == nil {
		return false
	}

	rt, err := filter.GetUDP6Table(d.buff)
	if err != nil {
		return false
	}

	p := uint32(b[ipv6.HeaderLen]) | uint32(b[ipv6.HeaderLen+1])<<8
	a := *(*[4]uint32)(unsafe.Pointer(&b[0]))

	for i := range rt {
		if rt[i].LocalPort == p {
			if (0 == rt[i].LocalAddr[0] && 0 == rt[i].LocalAddr[1] && 0 == rt[i].LocalAddr[2] && 0 == rt[i].LocalAddr[3]) ||
				(a[0] == rt[i].LocalAddr[0] && a[1] == rt[i].LocalAddr[1] && a[2] == rt[i].LocalAddr[2] && a[3] == rt[i].LocalAddr[3]) {
				return d.AppFilter.Lookup(rt[i].OwningPid)
			}
		}
	}

	return false
}
