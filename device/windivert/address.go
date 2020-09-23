package windivert

import (
	"unsafe"
)

type Ethernet struct {
	InterfaceIndex    uint32
	SubInterfaceIndex uint32
	_                 [7]uint64
}

type Network struct {
	InterfaceIndex    uint32
	SubInterfaceIndex uint32
	_                 [7]uint64
}

type Socket struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddress     [16]uint8
	RemoteAddress    [16]uint8
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [3]uint8
	_                uint32
}

type Flow struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddress     [16]uint8
	RemoteAddress    [16]uint8
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [3]uint8
	_                uint32
}

type Reflect struct {
	TimeStamp int64
	ProcessID uint32
	layer     uint32
	Flags     uint64
	Priority  int16
	_         int16
	_         int32
	_         [4]uint64
}

func (r *Reflect) Layer() Layer {
	return Layer(r.layer)
}

type Address struct {
	Timestamp int64
	layer     uint8
	event     uint8
	Flags     uint8
	_         uint8
	length    uint32
	union     [64]uint8
}

func (a *Address) Layer() Layer {
	return Layer(a.layer)
}

func (a *Address) Event() Event {
	return Event(a.event)
}

func (a *Address) Ethernet() *Ethernet {
	return (*Ethernet)(unsafe.Pointer(&a.union))
}

func (a *Address) Network() *Network {
	return (*Network)(unsafe.Pointer(&a.union))
}

func (a *Address) Socket() *Socket {
	return (*Socket)(unsafe.Pointer(&a.union))
}

func (a *Address) Flow() *Flow {
	return (*Flow)(unsafe.Pointer(&a.union))
}

func (a *Address) Reflect() *Reflect {
	return (*Reflect)(unsafe.Pointer(&a.union))
}
