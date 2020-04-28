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

	"github.com/imgk/shadow/internal/iana"
	"github.com/imgk/shadow/utils"
)

type Device struct {
	*Address
	*io.PipeReader
	*io.PipeWriter
	*utils.AppFilter
	*utils.IPFilter
	RecvHd *Handle
	SendHd *Handle
	TCP    [65536]uint8
	UDP    [65536]uint8
	TCP6   [65536]uint8
	UDP6   [65536]uint8
	active chan struct{}
	event  chan struct{}
}

func NewDevice(filter string) (dev *Device, err error) {
	CloseWhenError := func(hd *Handle) {
		if err != nil {
			hd.Close()
		}
	}

	ifIdx, subIfIdx, er := GetInterfaceIndex()
	if er != nil {
		err = er
		return
	}

	filter = fmt.Sprintf("ifIdx = %d and ", ifIdx) + filter
	recv, er := Open(filter, LayerNetwork, PriorityDefault, FlagDefault)
	if er != nil {
		err = fmt.Errorf("open recv handle error: %v", er)
		return
	}
	defer CloseWhenError(recv)

	if er := recv.SetParam(QueueLength, QueueLengthMax); er != nil {
		err = fmt.Errorf("set recv handle parameter queue length error %v", er)
		return
	}
	if er := recv.SetParam(QueueTime, QueueTimeMax); er != nil {
		err = fmt.Errorf("set recv handle parameter queue time error %v", er)
		return
	}
	if er := recv.SetParam(QueueSize, QueueSizeMax); er != nil {
		err = fmt.Errorf("set recv handle parameter queue size error %v", er)
		return
	}

	send, err := Open("false", LayerNetwork, PriorityDefault, FlagDefault)
	if err != nil {
		err = fmt.Errorf("open send handle error: %v", err)
		return
	}

	r, w := io.Pipe()
	dev = &Device{
		Address:    new(Address),
		PipeReader: r,
		PipeWriter: w,
		AppFilter:  utils.NewAppFilter(),
		IPFilter:   utils.NewIPFilter(),
		RecvHd:     recv,
		SendHd:     send,
		active:     make(chan struct{}),
		event:      make(chan struct{}, 1),
	}

	go dev.writeLoop()

	nw := dev.Address.Network()
	nw.InterfaceIndex = ifIdx
	nw.SubInterfaceIndex = subIfIdx

	return
}

func (d *Device) Close() error {
	select {
	case <-d.active:
		return nil
	default:
		close(d.active)
		close(d.event)
	}
	defer d.SendHd.Close()
	defer d.RecvHd.Close()

	d.PipeReader.Close()
	d.PipeWriter.Close()

	if err := d.SendHd.Shutdown(ShutdownBoth); err != nil {
		return fmt.Errorf("shutdown send handle error: %v", err)
	}

	if err := d.RecvHd.Shutdown(ShutdownBoth); err != nil {
		return fmt.Errorf("shutdown recv handle error: %v", err)
	}

	if err := d.RecvHd.Close(); err != nil {
		return fmt.Errorf("close recv handle error: %v", err)
	}

	if err := d.SendHd.Close(); err != nil {
		return fmt.Errorf("close send handle error: %v", err)
	}

	return nil
}

func (d *Device) Read(b []byte) (int, error) {
	return 0, errors.New("not support")
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	a := make([]Address, BatchMax)
	b := make([]byte, 1500*BatchMax)

	const f = uint8(0x01<<7) | uint8(0x01<<6) | uint8(0x01<<5) | uint8(0x01<<3)

	for {
		nr, nx, er := d.RecvHd.RecvEx(b, a, nil)
		if er != nil {
			select {
			case <-d.active:
			default:
				if er != ErrNoData {
					err = fmt.Errorf("RecvEx in WriteTo error: %v", er)
				}
			}

			return
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

		_, er = d.RecvHd.SendEx(b[:nr], a[:nx], nil)
		if er != nil && er != ErrHostUnreachable {
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
	case iana.ProtocolTCP:
		p := uint32(b[ipv4.HeaderLen])<<8 | uint32(b[ipv4.HeaderLen+1])
		switch d.TCP[p] {
		case 0:
			if b[ipv4.HeaderLen+13]&SYN != SYN {
				d.TCP[p] = 1

				return false
			}

			if d.IPFilter.Lookup(net.IP(b[16:20])) {
				d.TCP[p] = 2

				return true
			}

			if d.CheckTCP4(b) {
				d.TCP[p] = 2

				return true
			}

			d.TCP[p] = 1

			return false
		case 1:
			if b[ipv4.HeaderLen+13]&FIN == FIN {
				d.TCP[p] = 0
			}

			return false
		case 2:
			if b[ipv4.HeaderLen+13]&FIN == FIN {
				d.TCP[p] = 0
			}

			return true
		}
	case iana.ProtocolUDP:
		p := uint32(b[ipv4.HeaderLen])<<8 | uint32(b[ipv4.HeaderLen+1])
		switch d.UDP[p] {
		case 0:
			if d.IPFilter.Lookup(net.IP(b[16:20])) {
				d.UDP[p] = 2
				time.AfterFunc(time.Minute, func() { d.UDP[p] = 0 })

				return true
			}

			if d.CheckUDP4(b) {
				d.UDP[p] = 2
				time.AfterFunc(time.Minute, func() { d.UDP[p] = 0 })

				return true
			}

			d.UDP[p] = 1
			time.AfterFunc(time.Minute, func() { d.UDP[p] = 0 })

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

func (d *Device) CheckTCP4(b []byte) bool {
	rs, err := utils.GetTCPTable()
	if err != nil {
		return false
	}

	p := uint32(b[ipv4.HeaderLen]) | uint32(b[ipv4.HeaderLen+1])<<8

	for i := range rs {
		if rs[i].LocalPort == p {
			if *(*uint32)(unsafe.Pointer(&b[12])) == rs[i].LocalAddr {
				return d.AppFilter.Lookup(rs[i].OwningPid)
			}
		}
	}

	return false
}

func (d *Device) CheckUDP4(b []byte) bool {
	rs, err := utils.GetUDPTable()
	if err != nil {
		return false
	}

	p := uint32(b[ipv4.HeaderLen]) | uint32(b[ipv4.HeaderLen+1])<<8

	for i := range rs {
		if rs[i].LocalPort == p {
			if *(*uint32)(unsafe.Pointer(&b[12])) == rs[i].LocalAddr {
				return d.AppFilter.Lookup(rs[i].OwningPid)
			}
		}
	}

	return false
}

func (d *Device) CheckIPv6(b []byte) bool {
	switch b[6] {
	case iana.ProtocolTCP:
		p := uint32(b[ipv6.HeaderLen])<<8 | uint32(b[ipv6.HeaderLen+1])
		switch d.TCP6[p] {
		case 0:
			if b[ipv6.HeaderLen+13]&SYN != SYN {
				d.TCP6[p] = 1

				return false
			}

			if d.IPFilter.Lookup(net.IP(b[24:40])) {
				d.TCP6[p] = 2

				return true
			}

			if d.CheckTCP6(b) {
				d.TCP6[p] = 2

				return true
			}

			d.TCP6[p] = 1

			return false
		case 1:
			if b[ipv6.HeaderLen+13]&FIN == FIN {
				d.TCP6[p] = 0
			}

			return false
		case 2:
			if b[ipv6.HeaderLen+13]&FIN == FIN {
				d.TCP6[p] = 0
			}

			return true
		}
	case iana.ProtocolUDP:
		p := uint32(b[ipv6.HeaderLen])<<8 | uint32(b[ipv6.HeaderLen+1])
		switch d.UDP6[p] {
		case 0:
			if d.IPFilter.Lookup(net.IP(b[24:40])) {
				d.UDP6[p] = 2
				time.AfterFunc(time.Minute, func() { d.UDP6[p] = 0 })

				return true
			}

			if d.CheckUDP6(b) {
				d.UDP6[p] = 2
				time.AfterFunc(time.Minute, func() { d.UDP6[p] = 0 })

				return true
			}

			d.UDP6[p] = 1
			time.AfterFunc(time.Minute, func() { d.UDP6[p] = 0 })

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

func (d *Device) CheckTCP6(b []byte) bool {
	rs, err := utils.GetTCP6Table()
	if err != nil {
		return false
	}

	p := uint32(b[ipv6.HeaderLen]) | uint32(b[ipv6.HeaderLen+1])<<8
	a := *(*[4]uint32)(unsafe.Pointer(&b[8]))

	for i := range rs {
		if rs[i].LocalPort == p {
			if a[0] == rs[i].LocalAddr[0] && a[1] == rs[i].LocalAddr[1] && a[2] == rs[i].LocalAddr[2] && a[3] == rs[i].LocalAddr[3] {
				return d.AppFilter.Lookup(rs[i].OwningPid)
			}
		}
	}

	return false
}

func (d *Device) CheckUDP6(b []byte) bool {
	rs, err := utils.GetUDP6Table()
	if err != nil {
		return false
	}

	p := uint32(b[ipv6.HeaderLen]) | uint32(b[ipv6.HeaderLen+1])<<8
	a := *(*[4]uint32)(unsafe.Pointer(&b[0]))

	for i := range rs {
		if rs[i].LocalPort == p {
			if a[0] == rs[i].LocalAddr[0] && a[1] == rs[i].LocalAddr[1] && a[2] == rs[i].LocalAddr[2] && a[3] == rs[i].LocalAddr[3] {
				return d.AppFilter.Lookup(rs[i].OwningPid)
			}
		}
	}

	return false
}

func (d *Device) writeLoop() {
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()

	const f = uint8(0x01<<7) | uint8(0x01<<6) | uint8(0x01<<5)

	a := make([]Address, BatchMax)
	b := make([]byte, 1500*BatchMax)

	for i := range a {
		a[i] = *d.Address
		a[i].Flags |= f
	}

	n, m := 0, 0
	for {
		select {
		case <-t.C:
			if m > 0 {
				_, err := d.SendHd.SendEx(b[:n], a[:m], nil)
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
			nr, err := d.PipeReader.Read(b[n:])
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

			if m == BatchMax {
				_, err := d.SendHd.SendEx(b[:n], a[:m], nil)
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
		}
	}
}

func (d *Device) Write(b []byte) (int, error) {
	select {
	case <-d.active:
		return 0, io.EOF
	default:
		d.event <- struct{}{}
	}

	n, err := d.PipeWriter.Write(b)
	if err != nil {
		select {
		case <-d.active:
			return 0, io.EOF
		default:
		}
	}

	return n, err
}

func (d *Device) ReadFrom(r io.Reader) (n int64, err error) {
	err = errors.New("not support")
	return
}
