package windivert

import (
	"errors"
	"fmt"
	"io"

	"github.com/imgk/shadowsocks-windivert/netstack"
)

type Device struct {
	*Handle
	*Address
}

func NewDevice(filter string) (netstack.Device, error) {
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

	dev := &Device{
		Handle:  hd,
		Address: new(Address),
	}

	nw := dev.Address.Network()
	nw.InterfaceIndex = interfaceIndex
	nw.SubInterfaceIndex = subInterfaceIndex

	return dev, nil
}

func (d *Device) Close() error {
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

func (d *Device) WriteTo(w io.Writer) (int64, error) {
	b := make([]byte, 1500*BatchMax)

	for {
		nr, _, err := d.Handle.RecvEx(b, nil, nil)
		if err != nil {
			if err == ErrNoData {
				return 0, nil
			}
			return 0, err
		}

		bb := b[:nr]
		for len(bb) > 0 {
			l := int(b[2])<<8 | int(b[3])

			_, err = w.Write(b[:l])
			if err != nil {
				return 0, err
			}

			bb = bb[l:]
		}
	}
}

func (d *Device) Write(b []byte) (int, error) {
	n, err := d.Handle.Send(b, d.Address)
	return int(n), err
}

func (d *Device) ReadFrom(r io.Reader) (int64, error) {
	//TODO
	return 0, errors.New("not support")
}
