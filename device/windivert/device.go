// +build windows

package windivert

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/imgk/divert-go"

	"github.com/imgk/shadow/common"
)

const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

type Device struct {
	address *divert.Address
	handle  *divert.Handle

	appFilter *common.AppFilter
	ipFilter  *common.IPFilter
	hijack    bool

	r *io.PipeReader
	w *io.PipeWriter

	TCP4Map [65536]uint8
	UDP4Map [65536]uint8
	TCP6Map [65536]uint8
	UDP6Map [65536]uint8

	active chan struct{}
	event  chan struct{}
}

func NewDevice(filter string, appFilter *common.AppFilter, ipFilter *common.IPFilter, hijack bool) (dev *Device, err error) {
	ifIdx, subIfIdx, er := GetInterfaceIndex()
	if er != nil {
		err = er
		return
	}

	filter = fmt.Sprintf("ifIdx = %d and ", ifIdx) + filter
	hd, er := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if er != nil {
		err = fmt.Errorf("open handle error: %w", er)
		return
	}
	defer func(hd *divert.Handle) {
		if err != nil {
			hd.Close()
		}
	}(hd)

	if er := hd.SetParam(divert.QueueLength, divert.QueueLengthMax); er != nil {
		err = fmt.Errorf("set handle parameter queue length error: %w", er)
		return
	}
	if er := hd.SetParam(divert.QueueTime, divert.QueueTimeMax); er != nil {
		err = fmt.Errorf("set handle parameter queue time error: %w", er)
		return
	}
	if er := hd.SetParam(divert.QueueSize, divert.QueueSizeMax); er != nil {
		err = fmt.Errorf("set handle parameter queue size error: %w", er)
		return
	}

	r, w := io.Pipe()
	dev = &Device{
		address:   new(divert.Address),
		handle:    hd,
		appFilter: appFilter,
		ipFilter:  ipFilter,
		hijack:    hijack,
		r:         r,
		w:         w,
		active:    make(chan struct{}),
		event:     make(chan struct{}, 1),
	}

	nw := dev.address.Network()
	nw.InterfaceIndex = ifIdx
	nw.SubInterfaceIndex = subIfIdx

	go dev.writeLoop()

	return
}

func (d *Device) Close() (err error) {
	select {
	case <-d.active:
		return nil
	default:
		close(d.active)
	}
	defer func() {
		if er := d.handle.Close(); er != nil {
			err = fmt.Errorf("close handle error: %w", er)
		}
	}()

	d.ipFilter.Close()
	d.r.Close()
	d.w.Close()

	if err := d.handle.Shutdown(divert.ShutdownBoth); err != nil {
		return fmt.Errorf("shutdown handle error: %w", err)
	}
	return
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	a := make([]divert.Address, divert.BatchMax)
	b := make([]byte, 1500*divert.BatchMax)

	const f = uint8(0x01<<7) | uint8(0x01<<6) | uint8(0x01<<5) | uint8(0x01<<3)

	for {
		nr, nx, er := d.handle.RecvEx(b, a)
		if er != nil {
			select {
			case <-d.active:
			default:
				if er != divert.ErrNoData {
					err = fmt.Errorf("RecvEx in WriteTo error: %v", er)
				}
			}

			return
		}
		if nr < 1 || nx < 1 {
			continue
		}

		n += int64(nr)

		bb := b[:nr]
		for i := uint(0); i < nx; i++ {
			switch bb[0] >> 4 {
			case ipv4.Version:
				l := int(bb[2])<<8 | int(bb[3])

				if d.CheckIPv4(bb) {
					_, er := w.Write(bb[:l])
					if er != nil {
						select {
						case <-d.active:
						default:
							err = fmt.Errorf("Write in WriteTo error: %v", er)
						}

						return
					}

					a[i].Flags |= f

					bb[8] = 0
				}

				bb = bb[l:]
			case ipv6.Version:
				l := int(bb[4])<<8 | int(bb[5]) + ipv6.HeaderLen

				if d.CheckIPv6(bb) {
					_, er := w.Write(bb[:l])
					if er != nil {
						select {
						case <-d.active:
						default:
							err = fmt.Errorf("Write in WriteTo error: %v", er)
						}

						return
					}

					a[i].Flags |= f

					bb[7] = 0
				}

				bb = bb[l:]
			default:
				err = errors.New("invalid ip version")
				return
			}
		}

		d.handle.Lock()
		_, er = d.handle.SendEx(b[:nr], a[:nx])
		d.handle.Unlock()
		if er != nil && er != divert.ErrHostUnreachable {
			select {
			case <-d.active:
			default:
				err = fmt.Errorf("SendEx in WriteTo error: %v", er)
			}

			return
		}
	}
}

const (
	FIN = 1 << 0
	SYN = 1 << 1
	RST = 1 << 2
	PSH = 1 << 3
	ACK = 1 << 4
	UGR = 1 << 5
	ECE = 1 << 6
	CWR = 1 << 7
)

func (d *Device) CheckIPv4(b []byte) bool {
	switch b[9] {
	case ProtocolTCP:
		p := uint32(b[ipv4.HeaderLen])<<8 | uint32(b[ipv4.HeaderLen+1])
		switch d.TCP4Map[p] {
		case 0:
			if b[ipv4.HeaderLen+13]&SYN != SYN {
				d.TCP4Map[p] = 1
				return false
			}

			if d.ipFilter.Lookup(net.IP(b[16:20])) {
				d.TCP4Map[p] = 2
				return true
			}

			if d.CheckTCP4ByPID(b) {
				d.TCP4Map[p] = 2
				return true
			}

			d.TCP4Map[p] = 1
			return false
		case 1:
			if b[ipv4.HeaderLen+13]&FIN == FIN {
				d.TCP4Map[p] = 0
			}

			return false
		case 2:
			if b[ipv4.HeaderLen+13]&FIN == FIN {
				d.TCP4Map[p] = 0
			}

			return true
		}
	case ProtocolUDP:
		p := uint32(b[ipv4.HeaderLen])<<8 | uint32(b[ipv4.HeaderLen+1])

		switch d.UDP4Map[p] {
		case 0:
			fn := func() { d.UDP4Map[p] = 0 }

			if d.ipFilter.Lookup(net.IP(b[16:20])) {
				d.UDP4Map[p] = 2
				time.AfterFunc(time.Minute, fn)
				return true
			}

			if d.CheckUDP4ByPID(b) {
				d.UDP4Map[p] = 2
				time.AfterFunc(time.Minute, fn)
				return true
			}

			if (uint32(b[ipv4.HeaderLen+2])<<8|uint32(b[ipv4.HeaderLen+3])) == 53 && d.hijack {
				return true
			}

			d.UDP4Map[p] = 1
			time.AfterFunc(time.Minute, fn)

			return false
		case 1:
			return false
		case 2:
			return true
		}
	default:
		return d.ipFilter.Lookup(net.IP(b[16:20]))
	}

	return false
}

func (d *Device) CheckTCP4ByPID(b []byte) bool {
	if d.appFilter == nil {
		return false
	}

	rs, err := common.GetTCPTable()
	if err != nil {
		return false
	}

	p := uint32(b[ipv4.HeaderLen]) | uint32(b[ipv4.HeaderLen+1])<<8

	for i := range rs {
		if rs[i].LocalPort == p {
			if *(*uint32)(unsafe.Pointer(&b[12])) == rs[i].LocalAddr {
				return d.appFilter.Lookup(rs[i].OwningPid)
			}
		}
	}

	return false
}

func (d *Device) CheckUDP4ByPID(b []byte) bool {
	if d.appFilter == nil {
		return false
	}

	rs, err := common.GetUDPTable()
	if err != nil {
		return false
	}

	p := uint32(b[ipv4.HeaderLen]) | uint32(b[ipv4.HeaderLen+1])<<8

	for i := range rs {
		if rs[i].LocalPort == p {
			if 0 == rs[i].LocalAddr || *(*uint32)(unsafe.Pointer(&b[12])) == rs[i].LocalAddr {
				return d.appFilter.Lookup(rs[i].OwningPid)
			}
		}
	}

	return false
}

func (d *Device) CheckIPv6(b []byte) bool {
	switch b[6] {
	case ProtocolTCP:
		p := uint32(b[ipv6.HeaderLen])<<8 | uint32(b[ipv6.HeaderLen+1])
		switch d.TCP6Map[p] {
		case 0:
			if b[ipv6.HeaderLen+13]&SYN != SYN {
				d.TCP6Map[p] = 1
				return false
			}

			if d.ipFilter.Lookup(net.IP(b[24:40])) {
				d.TCP6Map[p] = 2
				return true
			}

			if d.CheckTCP6ByPID(b) {
				d.TCP6Map[p] = 2
				return true
			}

			d.TCP6Map[p] = 1
			return false
		case 1:
			if b[ipv6.HeaderLen+13]&FIN == FIN {
				d.TCP6Map[p] = 0
			}

			return false
		case 2:
			if b[ipv6.HeaderLen+13]&FIN == FIN {
				d.TCP6Map[p] = 0
			}

			return true
		}
	case ProtocolUDP:
		p := uint32(b[ipv6.HeaderLen])<<8 | uint32(b[ipv6.HeaderLen+1])

		switch d.UDP6Map[p] {
		case 0:
			fn := func() { d.UDP6Map[p] = 0 }

			if d.ipFilter.Lookup(net.IP(b[24:40])) {
				d.UDP6Map[p] = 2
				time.AfterFunc(time.Minute, fn)
				return true
			}

			if d.CheckUDP6ByPID(b) {
				d.UDP6Map[p] = 2
				time.AfterFunc(time.Minute, fn)
				return true
			}

			if (uint32(b[ipv6.HeaderLen+2])<<8|uint32(b[ipv6.HeaderLen+3])) == 53 && d.hijack {
				return true
			}

			d.UDP6Map[p] = 1
			time.AfterFunc(time.Minute, fn)
			return false
		case 1:
			return false
		case 2:
			return true
		}
	default:
		return d.ipFilter.Lookup(net.IP(b[24:40]))
	}

	return false
}

func (d *Device) CheckTCP6ByPID(b []byte) bool {
	if d.appFilter == nil {
		return false
	}

	rs, err := common.GetTCP6Table()
	if err != nil {
		return false
	}

	p := uint32(b[ipv6.HeaderLen]) | uint32(b[ipv6.HeaderLen+1])<<8
	a := *(*[4]uint32)(unsafe.Pointer(&b[8]))

	for i := range rs {
		if rs[i].LocalPort == p {
			if a[0] == rs[i].LocalAddr[0] && a[1] == rs[i].LocalAddr[1] && a[2] == rs[i].LocalAddr[2] && a[3] == rs[i].LocalAddr[3] {
				return d.appFilter.Lookup(rs[i].OwningPid)
			}
		}
	}

	return false
}

func (d *Device) CheckUDP6ByPID(b []byte) bool {
	if d.appFilter == nil {
		return false
	}

	rs, err := common.GetUDP6Table()
	if err != nil {
		return false
	}

	p := uint32(b[ipv6.HeaderLen]) | uint32(b[ipv6.HeaderLen+1])<<8
	a := *(*[4]uint32)(unsafe.Pointer(&b[0]))

	for i := range rs {
		if rs[i].LocalPort == p {
			if (0 == rs[i].LocalAddr[0] && 0 == rs[i].LocalAddr[1] && 0 == rs[i].LocalAddr[2] && 0 == rs[i].LocalAddr[3]) || (a[0] == rs[i].LocalAddr[0] && a[1] == rs[i].LocalAddr[1] && a[2] == rs[i].LocalAddr[2] && a[3] == rs[i].LocalAddr[3]) {
				return d.appFilter.Lookup(rs[i].OwningPid)
			}
		}
	}

	return false
}

func (d *Device) writeLoop() {
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()

	const f = uint8(0x01<<7) | uint8(0x01<<6) | uint8(0x01<<5)

	a := make([]divert.Address, divert.BatchMax)
	b := make([]byte, 1500*divert.BatchMax)

	for i := range a {
		a[i] = *d.address
		a[i].Flags |= f
	}

	n, m := 0, 0
	for {
		select {
		case <-t.C:
			if m > 0 {
				d.handle.Lock()
				_, err := d.handle.SendEx(b[:n], a[:m])
				d.handle.Unlock()
				if err != nil {
					select {
					case <-d.active:
					default:
						panic(fmt.Errorf("device writeLoop error: %v", err))
					}

					return
				}

				n, m = 0, 0
			}
		case <-d.event:
			nr, err := d.r.Read(b[n:])
			if err != nil {
				select {
				case <-d.active:
				default:
					panic(fmt.Errorf("device writeLoop error: %v", err))
				}

				return
			}

			n += nr
			m++

			if m == divert.BatchMax {
				d.handle.Lock()
				_, err := d.handle.SendEx(b[:n], a[:m])
				d.handle.Unlock()
				if err != nil {
					select {
					case <-d.active:
					default:
						panic(fmt.Errorf("device writeLoop error: %v", err))
					}

					return
				}

				n, m = 0, 0
			}
		case <-d.active:
			return
		}
	}
}

func (d *Device) Write(b []byte) (int, error) {
	select {
	case <-d.active:
		return 0, io.EOF
	case d.event <- struct{}{}:
	}

	n, err := d.w.Write(b)
	if err != nil {
		select {
		case <-d.active:
			return 0, io.EOF
		default:
		}
	}

	return n, err
}
