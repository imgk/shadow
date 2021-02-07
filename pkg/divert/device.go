// +build windows

package divert

import (
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/imgk/divert-go"

	"github.com/imgk/shadow/pkg/divert/filter"
)

// Device is ...
type Device struct {
	// Address is ...
	Address *divert.Address
	// Handle is ...
	Handle *divert.Handle
	// Filter is ...
	Filter *PacketFilter
	// Pipe is ...
	Pipe struct {
		// PipeReader is ...
		*io.PipeReader
		// PipeWriter is ...
		*io.PipeWriter
		// Event is ...
		Event chan struct{}
	}

	closed chan struct{}
}

// NewDevice is ...
func NewDevice(filter string, appFilter *filter.AppFilter, ipFilter *filter.IPFilter, hijack bool) (dev *Device, err error) {
	ifIdx, subIfIdx, err := GetInterfaceIndex()
	if err != nil {
		return nil, err
	}

	filter = fmt.Sprintf("ifIdx = %d and %s", ifIdx, filter)
	hd, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		err = fmt.Errorf("open handle error: %w", err)
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

	dev = &Device{
		Address: new(divert.Address),
		Handle:  hd,
		Filter: &PacketFilter{
			AppFilter: appFilter,
			IPFilter:  ipFilter,
			Hijack:    hijack,
			TCP4Table: make([]byte, 64<<10),
			UDP4Table: make([]byte, 64<<10),
			TCP6Table: make([]byte, 64<<10),
			UDP6Table: make([]byte, 64<<10),
			buff:      make([]byte, 32<<10),
		},
		closed: make(chan struct{}),
	}
	dev.Pipe.PipeReader, dev.Pipe.PipeWriter = io.Pipe()
	dev.Pipe.Event = make(chan struct{}, 1)

	nw := dev.Address.Network()
	nw.InterfaceIndex = ifIdx
	nw.SubInterfaceIndex = subIfIdx

	go dev.loop()

	return
}

// DeviceType is ...
func (d *Device) DeviceType() string {
	return "WinDivert"
}

// Close is ...
func (d *Device) Close() error {
	select {
	case <-d.closed:
		return nil
	default:
		close(d.closed)
	}

	// close mmdb file
	d.Filter.IPFilter.Close()
	// close io.PipeReader and io.PipeWriter
	d.Pipe.PipeReader.Close()
	d.Pipe.PipeWriter.Close()

	// close divert.Handle
	if err := d.Handle.Shutdown(divert.ShutdownBoth); err != nil {
		d.Handle.Close()
		return fmt.Errorf("shutdown handle error: %w", err)
	}
	if err := d.Handle.Close(); err != nil {
		return fmt.Errorf("close handle error: %w", err)
	}
	return nil
}

// WriteTo is ...
func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	addr := make([]divert.Address, divert.BatchMax)
	buff := make([]byte, 1500*divert.BatchMax)

	const flags = uint8(0x01<<7) | uint8(0x01<<6) | uint8(0x01<<5) | uint8(0x01<<3)
	for {
		nb, nx, er := d.Handle.RecvEx(buff, addr)
		if er != nil {
			err = fmt.Errorf("handle recv error: %w", er)
			break
		}
		if nb < 1 || nx < 1 {
			continue
		}

		n += int64(nb)

		bb := buff[:nb]
		for i := uint(0); i < nx; i++ {
			switch bb[0] >> 4 {
			case ipv4.Version:
				l := int(bb[2])<<8 | int(bb[3])
				if d.Filter.CheckIPv4(bb) {
					if _, ew := w.Write(bb[:l]); ew != nil {
						err = ew
						break
					}
					// set address flag to NoChecksum to avoid calculate checksum
					addr[i].Flags |= flags
					// set TTL to 0
					bb[8] = 0
				}
				bb = bb[l:]
			case ipv6.Version:
				l := int(bb[4])<<8 | int(bb[5]) + ipv6.HeaderLen
				if d.Filter.CheckIPv6(bb) {
					if _, ew := w.Write(bb[:l]); ew != nil {
						err = ew
						break
					}
					// set address flag to NoChecksum to avoid calculate checksum
					addr[i].Flags |= flags
					// set TTL to 0
					bb[7] = 0
				}
				bb = bb[l:]
			default:
				err = errors.New("invalid ip version")
				break
			}
		}

		d.Handle.Lock()
		_, ew := d.Handle.SendEx(buff[:nb], addr[:nx])
		d.Handle.Unlock()
		if ew == nil || errors.Is(ew, divert.ErrHostUnreachable) {
			continue
		}
		err = ew
		break
	}
	if err != nil {
		select {
		case <-d.closed:
			err = nil
		default:
		}
	}
	return
}

// loop is ...
func (d *Device) loop() (err error) {
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()

	const flags = uint8(0x01<<7) | uint8(0x01<<6) | uint8(0x01<<5)

	addr := make([]divert.Address, divert.BatchMax)
	buff := make([]byte, 1500*divert.BatchMax)

	for i := range addr {
		addr[i] = *d.Address
		addr[i].Flags |= flags
	}

	nb, nx := 0, 0
LOOP:
	for {
		select {
		case <-t.C:
			if nx > 0 {
				d.Handle.Lock()
				_, ew := d.Handle.SendEx(buff[:nb], addr[:nx])
				d.Handle.Unlock()
				if ew != nil {
					err = fmt.Errorf("device loop error: %w", ew)
					break LOOP
				}
				nb, nx = 0, 0
			}
		case <-d.Pipe.Event:
			nr, er := d.Pipe.Read(buff[nb:])
			if er != nil {
				err = fmt.Errorf("device loop error: %w", er)
				break LOOP
			}

			nb += nr
			nx++

			if nx < divert.BatchMax {
				continue
			}

			d.Handle.Lock()
			_, ew := d.Handle.SendEx(buff[:nb], addr[:nx])
			d.Handle.Unlock()
			if ew != nil {
				err = fmt.Errorf("device loop error: %w", ew)
				break LOOP
			}
			nb, nx = 0, 0
		case <-d.closed:
			return
		}
	}
	if err != nil {
		select {
		case <-d.closed:
		default:
			log.Panic(err)
		}
	}
	return nil
}

// Write is ...
func (d *Device) Write(b []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.EOF
	case d.Pipe.Event <- struct{}{}:
	}

	n, err := d.Pipe.Write(b)
	if err != nil {
		select {
		case <-d.closed:
			return 0, io.EOF
		default:
		}
	}

	return n, err
}
