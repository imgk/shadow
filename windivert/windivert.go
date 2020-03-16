package windivert

// #cgo CFLAGS: -I${SRCDIR}/Divert/include
// #define WINDIVERTEXPORT static
// #include "Divert/dll/windivert.c"
import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var version string

func Version() string {
	return version
}

func init() {
	var vers = map[string]struct{}{
		"2.0": struct{}{},
		"2.1": struct{}{},
		"2.2": struct{}{},
	}

	hd, err := Open("false", LayerNetwork, PriorityDefault, FlagDefault)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := hd.Close(); err != nil {
			panic(err)
		}
	}()

	major, err := hd.GetParam(VersionMajor)
	if err != nil {
		panic(err)
	}

	minor, err := hd.GetParam(VersionMinor)
	if err != nil {
		panic(err)
	}

	ver := strings.Join([]string{strconv.Itoa(int(major)), strconv.Itoa(int(minor))}, ".")
	if _, ok := vers[ver]; !ok {
		s := ""
		for k, _ := range vers {
			s += k
		}
		panic(fmt.Errorf("unsupported version %v of windivert, only support %v", ver, s))
	}

	version = ver
}

type Ethernet struct { // 64 bytes
	InterfaceIndex    uint32
	SubInterfaceIndex uint32
	_                 [7]uint64
}

type Network struct { // 64 bytes
	InterfaceIndex    uint32
	SubInterfaceIndex uint32
	_                 [7]uint64
}

type Socket struct { // 64 bytes
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddress     [4]uint32
	RemoteAddress    [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [3]uint8
	_                uint32 // GOARCH=386
}

type Flow struct { // 64 bytes
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddress     [4]uint32
	RemoteAddress    [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [3]uint8
	_                uint32 // GOARCH=386
}

type Reflect struct { // 64 bytes
	TimeStamp int64
	ProcessID uint32
	layer     uint32
	Flags     uint64
	Priority  int16
	_         int16
	_         int32
	_         [4]uint64
}

func (r *Reflect) Layer() C.WINDIVERT_LAYER {
	return C.WINDIVERT_LAYER(r.layer)
}

type Address struct { // 80 bytes
	Timestamp int64
	layer     uint8
	event     uint8
	flags     uint8
	_         uint8
	length    uint32
	union     [64]uint8
}

func (a *Address) Layer() C.WINDIVERT_LAYER {
	return C.WINDIVERT_LAYER(a.layer)
}

func (a *Address) SetLayer(layer C.WINDIVERT_LAYER) {
	a.layer = uint8(layer)
}

func (a *Address) Event() C.WINDIVERT_EVENT {
	return C.WINDIVERT_EVENT(a.event)
}

func (a *Address) SetEvent(event C.WINDIVERT_EVENT) {
	a.event = uint8(event)
}

func (a *Address) Sniffed() bool {
	return (a.flags & uint8(0x01<<0)) == uint8(0x01<<0)
}

func (a *Address) SetSniffed() {
	a.flags |= uint8(0x01 << 0)
}

func (a *Address) UnsetSniffed() {
	a.flags &= ^uint8(0x01 << 0)
}

func (a *Address) Outbound() bool {
	return (a.flags & uint8(0x01<<1)) == uint8(0x01<<1)
}

func (a *Address) SetOutbound() {
	a.flags |= uint8(0x01 << 1)
}

func (a *Address) UnsetOutbound() {
	a.flags &= ^uint8(0x01 << 1)
}

func (a *Address) Loopback() bool {
	return (a.flags & uint8(0x01<<2)) == uint8(0x01<<2)
}

func (a *Address) SetLoopback() {
	a.flags |= uint8(0x01 << 2)
}

func (a *Address) UnsetLoopback() {
	a.flags &= ^uint8(0x01 << 2)
}

func (a *Address) Impostor() bool {
	return (a.flags & uint8(0x01<<3)) == uint8(0x01<<3)
}

func (a *Address) SetImpostor() {
	a.flags |= uint8(0x01 << 3)
}

func (a *Address) UnsetImpostor() {
	a.flags &= ^uint8(0x01 << 3)
}

func (a *Address) IPv6() bool {
	return (a.flags & uint8(0x01<<4)) == uint8(0x01<<4)
}

func (a *Address) SetIPv6() {
	a.flags |= uint8(0x01 << 4)
}

func (a *Address) UnsetIPv6() {
	a.flags &= ^uint8(0x01 << 4)
}

func (a *Address) IPChecksum() bool {
	return (a.flags & uint8(0x01<<5)) == uint8(0x01<<5)
}

func (a *Address) SetIPChecksum() {
	a.flags |= uint8(0x01 << 5)
}

func (a *Address) UnsetIPChecksum() {
	a.flags &= ^uint8(0x01 << 5)
}

func (a *Address) TCPChecksum() bool {
	return (a.flags & uint8(0x01<<6)) == uint8(0x01<<6)
}

func (a *Address) SetTCPChecksum() {
	a.flags |= uint8(0x01 << 6)
}

func (a *Address) UnsetTCPChecksum() {
	a.flags &= ^uint8(0x01 << 6)
}

func (a *Address) UDPChecksum() bool {
	return (a.flags & uint8(0x01<<7)) == uint8(0x01<<7)
}

func (a *Address) SetUDPChecksum() {
	a.flags |= uint8(0x01 << 7)
}

func (a *Address) UnsetUDPChecksum() {
	a.flags &= ^uint8(0x01 << 7)
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

type Handle struct {
	windows.Handle
}

func Open(filter string, layer C.WINDIVERT_LAYER, priority int16, flags uint64) (*Handle, error) {
	if priority < int16(C.WINDIVERT_PRIORITY_LOWEST) || priority > int16(C.WINDIVERT_PRIORITY_HIGHEST) {
		return nil, fmt.Errorf("Priority %v is not Correct, Max: %v, Min: %v", priority, int16(C.WINDIVERT_PRIORITY_HIGHEST), int16(C.WINDIVERT_PRIORITY_LOWEST))
	}

	hd := C.WinDivertOpen(C.CString(filter), layer, C.int16_t(priority), C.uint64_t(flags))
	if hd == C.HANDLE(C.INVALID_HANDLE_VALUE) {
		return nil, GetLastError()
	}

	return &Handle{Handle: windows.Handle(hd)}, nil
}

func (h *Handle) Recv(buffer []byte, address *Address) (uint, error) {
	recvLen := uint(0)
	b := C.WinDivertRecv(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&recvLen)), C.PWINDIVERT_ADDRESS(unsafe.Pointer(address)))
	if b == C.FALSE {
		return 0, GetLastError()
	}

	return recvLen, nil
}

func (h *Handle) RecvEx(buffer []byte, address []Address, overlapped *windows.Overlapped) (uint, uint, error) {
	recvLen := uint(0)

	if address == nil || len(address) == 0 {
		b := C.WinDivertRecvEx(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&recvLen)), C.uint64_t(0), C.PWINDIVERT_ADDRESS(unsafe.Pointer(nil)), (*C.uint)(unsafe.Pointer(nil)), C.LPOVERLAPPED(unsafe.Pointer(overlapped)))
		if b == C.FALSE {
			return 0, 0, GetLastError()
		}

		return recvLen, 0, nil
	} else {
		addrLen := uint(len(address)) * uint(unsafe.Sizeof(C.WINDIVERT_ADDRESS{}))
		b := C.WinDivertRecvEx(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&recvLen)), C.uint64_t(0), C.PWINDIVERT_ADDRESS(unsafe.Pointer(&address[0])), (*C.uint)(unsafe.Pointer(&addrLen)), C.LPOVERLAPPED(unsafe.Pointer(overlapped)))
		if b == C.FALSE {
			return 0, 0, GetLastError()
		}
		addrLen /= uint(unsafe.Sizeof(C.WINDIVERT_ADDRESS{}))

		return recvLen, addrLen, nil
	}
}

func (h *Handle) Send(buffer []byte, address *Address) (uint, error) {
	sendLen := uint(0)
	b := C.WinDivertSend(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&sendLen)), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)))
	if b == C.FALSE {
		return 0, GetLastError()
	}

	return sendLen, nil
}

func (h *Handle) SendEx(buffer []byte, address []Address, overlapped *windows.Overlapped) (uint, error) {
	sendLen := uint(0)
	b := C.WinDivertSendEx(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&sendLen)), C.uint64_t(0), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(&address[0])), C.uint(uint(len(address))*uint(unsafe.Sizeof(C.WINDIVERT_ADDRESS{}))), C.LPOVERLAPPED(unsafe.Pointer(overlapped)))
	if b == C.FALSE {
		return 0, GetLastError()
	}

	return sendLen, nil
}

func (h *Handle) Shutdown(how C.WINDIVERT_SHUTDOWN) error {
	b := C.WinDivertShutdown(C.HANDLE(h.Handle), how)
	if b == C.FALSE {
		return GetLastError()
	}

	return nil
}

func (h *Handle) Close() error {
	b := C.WinDivertClose(C.HANDLE(h.Handle))
	if b == C.FALSE {
		return GetLastError()
	}

	return nil
}

func (h *Handle) GetParam(p C.WINDIVERT_PARAM) (uint64, error) {
	v := uint64(0)
	b := C.WinDivertGetParam(C.HANDLE(h.Handle), p, (*C.uint64_t)(unsafe.Pointer(&v)))
	if b == C.FALSE {
		err := GetLastError()
		return v, err
	}

	return v, nil
}

func (h *Handle) SetParam(p C.WINDIVERT_PARAM, v uint64) error {
	switch p {
	case C.WINDIVERT_PARAM_QUEUE_LENGTH:
		if v < uint64(C.WINDIVERT_PARAM_QUEUE_LENGTH_MIN) || v > uint64(C.WINDIVERT_PARAM_QUEUE_LENGTH_MAX) {
			return fmt.Errorf("Queue length %v is not correct, Max: %v, Min: %v", v, uint64(C.WINDIVERT_PARAM_QUEUE_LENGTH_MAX), uint64(C.WINDIVERT_PARAM_QUEUE_LENGTH_MIN))
		}
	case C.WINDIVERT_PARAM_QUEUE_TIME:
		if v < uint64(C.WINDIVERT_PARAM_QUEUE_TIME_MIN) || v > uint64(C.WINDIVERT_PARAM_QUEUE_TIME_MAX) {
			return fmt.Errorf("Queue time %v is not correct, Max: %v, Min: %v", v, uint64(C.WINDIVERT_PARAM_QUEUE_TIME_MAX), uint64(C.WINDIVERT_PARAM_QUEUE_TIME_MIN))
		}
	case C.WINDIVERT_PARAM_QUEUE_SIZE:
		if v < uint64(C.WINDIVERT_PARAM_QUEUE_SIZE_MIN) || v > uint64(C.WINDIVERT_PARAM_QUEUE_SIZE_MAX) {
			return fmt.Errorf("Queue size %v is not correct, Max: %v, Min: %v", v, uint64(C.WINDIVERT_PARAM_QUEUE_SIZE_MAX), uint64(C.WINDIVERT_PARAM_QUEUE_SIZE_MIN))
		}
	default:
		return errors.New("VersionMajor and VersionMinor only can be used in function GetParam")
	}

	b := C.WinDivertSetParam(C.HANDLE(h.Handle), p, C.uint64_t(v))
	if b == C.FALSE {
		return GetLastError()
	}

	return nil
}

func CalcChecksums(buffer []byte, layer C.WINDIVERT_LAYER, address *Address, flags uint64) error {
	//b := C.WinDivertHelperCalcChecksums(unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), layer, (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)), C.uint64_t(flags))
	b := C.WinDivertHelperCalcChecksums(unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)), C.uint64_t(flags))
	if b == C.FALSE {
		return GetLastError()
	}

	return nil
}
