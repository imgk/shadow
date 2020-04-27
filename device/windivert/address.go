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

func (a *Address) SetLayer(layer Layer) {
	a.layer = uint8(layer)
}

func (a *Address) Event() Event {
	return Event(a.event)
}

func (a *Address) SetEvent(event Event) {
	a.event = uint8(event)
}

func (a *Address) Sniffed() bool {
	return (a.Flags & uint8(0x01<<0)) == uint8(0x01<<0)
}

func (a *Address) SetSniffed() {
	a.Flags |= uint8(0x01 << 0)
}

func (a *Address) UnsetSniffed() {
	a.Flags &= ^uint8(0x01 << 0)
}

func (a *Address) Outbound() bool {
	return (a.Flags & uint8(0x01<<1)) == uint8(0x01<<1)
}

func (a *Address) SetOutbound() {
	a.Flags |= uint8(0x01 << 1)
}

func (a *Address) UnsetOutbound() {
	a.Flags &= ^uint8(0x01 << 1)
}

func (a *Address) Loopback() bool {
	return (a.Flags & uint8(0x01<<2)) == uint8(0x01<<2)
}

func (a *Address) SetLoopback() {
	a.Flags |= uint8(0x01 << 2)
}

func (a *Address) UnsetLoopback() {
	a.Flags &= ^uint8(0x01 << 2)
}

func (a *Address) Impostor() bool {
	return (a.Flags & uint8(0x01<<3)) == uint8(0x01<<3)
}

func (a *Address) SetImpostor() {
	a.Flags |= uint8(0x01 << 3)
}

func (a *Address) UnsetImpostor() {
	a.Flags &= ^uint8(0x01 << 3)
}

func (a *Address) IPv6() bool {
	return (a.Flags & uint8(0x01<<4)) == uint8(0x01<<4)
}

func (a *Address) SetIPv6() {
	a.Flags |= uint8(0x01 << 4)
}

func (a *Address) UnsetIPv6() {
	a.Flags &= ^uint8(0x01 << 4)
}

func (a *Address) IPChecksum() bool {
	return (a.Flags & uint8(0x01<<5)) == uint8(0x01<<5)
}

func (a *Address) SetIPChecksum() {
	a.Flags |= uint8(0x01 << 5)
}

func (a *Address) UnsetIPChecksum() {
	a.Flags &= ^uint8(0x01 << 5)
}

func (a *Address) TCPChecksum() bool {
	return (a.Flags & uint8(0x01<<6)) == uint8(0x01<<6)
}

func (a *Address) SetTCPChecksum() {
	a.Flags |= uint8(0x01 << 6)
}

func (a *Address) UnsetTCPChecksum() {
	a.Flags &= ^uint8(0x01 << 6)
}

func (a *Address) UDPChecksum() bool {
	return (a.Flags & uint8(0x01<<7)) == uint8(0x01<<7)
}

func (a *Address) SetUDPChecksum() {
	a.Flags |= uint8(0x01 << 7)
}

func (a *Address) UnsetUDPChecksum() {
	a.Flags &= ^uint8(0x01 << 7)
}

func (a *Address) Length() uint32 {
	return a.length >> 12
}

func (a *Address) SetLength(n uint32) {
	a.length = n << 12
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
