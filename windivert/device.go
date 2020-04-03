package windivert

import (
	"fmt"
	"io"
	"time"
)

type Device struct {
	*Handle
	*Address
	*io.PipeReader
	*io.PipeWriter
	active chan struct{}
	event  chan struct{}
}

func NewDevice(filter string) (*Device, error) {
	interfaceIndex, subInterfaceIndex, err := GetInterfaceIndex()
	if err != nil {
		return nil, err
	}

	filter = fmt.Sprintf("ifIdx = %d ", interfaceIndex) + filter
	hd, err := Open(filter, LayerNetwork, PriorityDefault, FlagDefault)
	if err != nil {
		return nil, fmt.Errorf("open handle error: %v", err)
	}
	if err := hd.SetParam(QueueLength, QueueLengthMax); err != nil {
		return nil, fmt.Errorf("set handle parameter queue length error %v", err)
	}
	if err := hd.SetParam(QueueTime, QueueTimeMax); err != nil {
		return nil, fmt.Errorf("set handle parameter queue time error %v", err)
	}
	if err := hd.SetParam(QueueSize, QueueSizeMax); err != nil {
		return nil, fmt.Errorf("set handle parameter queue size error %v", err)
	}

	r, w := io.Pipe()
	dev := &Device{
		Handle:  hd,
		Address: new(Address),
		PipeReader: r,
		PipeWriter: w,
		active: make(chan struct{}),
		event: make(chan struct{}, 1),
	}

	go dev.writeLoop()

	nw := dev.Address.Network()
	nw.InterfaceIndex = interfaceIndex
	nw.SubInterfaceIndex = subInterfaceIndex

	return dev, nil
}

func (d *Device) Close() error {
	select {
	case <- d.active:
		return nil
	default:
		close(d.active)
		close(d.event)
	}

	d.PipeReader.Close()
	d.PipeWriter.Close()

	if err := d.Handle.Shutdown(ShutdownBoth); err != nil {
		d.Handle.Close()
		return fmt.Errorf("shutdown handle error: %v", err)
	}

	if err := d.Handle.Close(); err != nil {
		return fmt.Errorf("close handle error: %v %v", err)
	}

	return nil
}

func (d *Device) Read(b []byte) (int, error) {
	n, err := d.Handle.Recv(b, nil)
	return int(n), err
}

func (d *Device) WriteTo(w io.Writer) (n int64, err error) {
	a := make([]Address, BatchMax)
	b := make([]byte, 1500*BatchMax)

	for {
		nr, _, er := d.Handle.RecvEx(b, a, nil)
		if er != nil {
			if er == ErrNoData {
				err = nil
			} else {
				err = er
			}
			return
		}

		n += int64(nr)

		bb := b[:nr]
		for len(bb) > 0 {
			l := int(bb[2])<<8 | int(bb[3])

			_, err = w.Write(bb[:l])
			if err != nil {
				return
			}

			bb = bb[l:]
		}
	}
}

func (d *Device) writeLoop() {
	defer d.Close()

	t := time.NewTicker(time.Millisecond)
	defer t.Stop()

	a := make([]Address, BatchMax)
	b := make([]byte, 1500*BatchMax)

	for i := range a {
		a[i] = *d.Address
	}

	n := 0
	m := 0
	for {
		select {
		case <- t.C:
			if m > 0 {
				if _, err := d.Handle.SendEx(b[:n], a[:m], nil); err != nil {
					return
				}
				n, m = 0, 0
			}
		case <- d.event:
			nr, err := d.PipeReader.Read(b[n:])
			if err != nil {
				return
			}

			n += nr
			m++

			if m == BatchMax {
				_, err := d.Handle.SendEx(b[:n], a[:m], nil)
				if err != nil {
					return
				}
				n, m = 0, 0
			}
		}
	}
}

func (d *Device) Write(b []byte) (int, error) {
	select {
	case <- d.active:
		return 0, io.EOF
	default:
		d.event <- struct{}{}
	}

	return d.PipeWriter.Write(b)
}

func (d *Device) ReadFrom(r io.Reader) (n int64, err error) {
	return
}
