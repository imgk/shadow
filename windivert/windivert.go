package windivert

// #cgo CFLAGS: -I${SRCDIR}/Divert/include
// #define WINDIVERTEXPORT static
// #include "Divert/dll/windivert.c"
import "C"

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func IoControl(h windows.Handle, code CtlCode, ioctl unsafe.Pointer, buf *byte, bufLen uint32, overlapped *windows.Overlapped) (iolen uint32, err error) {
	err = windows.DeviceIoControl(h, uint32(code), (*byte)(ioctl), uint32(unsafe.Sizeof(IoCtl{})), buf, bufLen, &iolen, overlapped)
	if err != windows.ERROR_IO_PENDING {
		return
	}

	err = windows.GetOverlappedResult(h, overlapped, &iolen, true)

	return
}

type Handle struct {
	windows.Handle
	windows.Overlapped
}

func Open(filter string, layer Layer, priority int16, flags uint64) (*Handle, error) {
	if priority < PriorityLowest || priority > PriorityHighest {
		return nil, fmt.Errorf("Priority %v is not Correct, Max: %v, Min: %v", priority, PriorityHighest, PriorityLowest)
	}

	hd := C.WinDivertOpen(C.CString(filter), C.WINDIVERT_LAYER(layer), C.int16_t(priority), C.uint64_t(flags))
	if windows.Handle(hd) == windows.InvalidHandle {
		return nil, Error(C.GetLastError())
	}

	event, _ := windows.CreateEvent(nil, 0, 0, nil)

	return &Handle{
		Handle: windows.Handle(hd),
		Overlapped: windows.Overlapped{
			HEvent: event,
		},
	}, nil
}

func (h Handle) Recv(buffer []byte, address *Address) (uint, error) {
	recvLen := uint(0)

	b := C.WinDivertRecv(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&recvLen)), C.PWINDIVERT_ADDRESS(unsafe.Pointer(address)))
	if b == C.FALSE {
		return 0, Error(C.GetLastError())
	}

	return recvLen, nil
}

func (h *Handle) RecvEx(buffer []byte, address []Address, overlapped *windows.Overlapped) (uint, uint, error) {
	addrLen := uint(len(address)) * uint(unsafe.Sizeof(Address{}))
	recv := Recv{
		Addr: uint64(uintptr(unsafe.Pointer(&address[0]))),
		AddrLenPtr: uint64(uintptr(unsafe.Pointer(&addrLen))),
	}

	iolen, err := IoControl(h.Handle, IoCtlRecv, unsafe.Pointer(&recv), &buffer[0], uint32(len(buffer)), &h.Overlapped)
	if err != nil {
		return uint(iolen), addrLen/uint(unsafe.Sizeof(Address{})), Error(err.(syscall.Errno))
	}

	return uint(iolen), addrLen/uint(unsafe.Sizeof(Address{})), nil
}

func (h *Handle) Send(buffer []byte, address *Address) (uint, error) {
	sendLen := uint(0)
	b := C.WinDivertSend(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&sendLen)), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)))
	if b == C.FALSE {
		return 0, Error(C.GetLastError())
	}

	return sendLen, nil
}

func (h *Handle) SendEx(buffer []byte, address []Address, overlapped *windows.Overlapped) (uint, error) {
	send := Send{
		Addr: uint64(uintptr(unsafe.Pointer(&address[0]))),
		AddrLen: uint64(unsafe.Sizeof(Address{}))*uint64(len(address)),
	}

	iolen, err := IoControl(h.Handle, IoCtlSend, unsafe.Pointer(&send), &buffer[0], uint32(len(buffer)), &h.Overlapped)
	if err != nil {
		return uint(iolen), Error(err.(syscall.Errno))
	}

	return uint(iolen), nil
}

func (h *Handle) Shutdown(how Shutdown) error {
	b := C.WinDivertShutdown(C.HANDLE(h.Handle), C.WINDIVERT_SHUTDOWN(how))
	if b == C.FALSE {
		return Error(C.GetLastError())
	}

	return nil
}

func (h *Handle) Close() error {
	windows.CloseHandle(h.Overlapped.HEvent)

	b := C.WinDivertClose(C.HANDLE(h.Handle))
	if b == C.FALSE {
		return Error(C.GetLastError())
	}

	return nil
}

func (h *Handle) GetParam(p Param) (uint64, error) {
	v := uint64(0)

	b := C.WinDivertGetParam(C.HANDLE(h.Handle), C.WINDIVERT_PARAM(p), (*C.uint64_t)(unsafe.Pointer(&v)))
	if b == C.FALSE {
		return v, Error(C.GetLastError())
	}

	return v, nil
}

func (h *Handle) SetParam(p Param, v uint64) error {
	switch p {
	case QueueLength:
		if v < QueueLengthMin || v > QueueLengthMax {
			return fmt.Errorf("Queue length %v is not correct, Max: %v, Min: %v", v, QueueLengthMax, QueueLengthMin)
		}
	case QueueTime:
		if v < QueueTimeMin || v > QueueTimeMax {
			return fmt.Errorf("Queue time %v is not correct, Max: %v, Min: %v", v, QueueTimeMax, QueueTimeMin)
		}
	case QueueSize:
		if v < QueueSizeMin || v > QueueSizeMax {
			return fmt.Errorf("Queue size %v is not correct, Max: %v, Min: %v", v, QueueSizeMax, QueueSizeMin)
		}
	default:
		return errors.New("VersionMajor and VersionMinor only can be used in function GetParam")
	}

	b := C.WinDivertSetParam(C.HANDLE(h.Handle), C.WINDIVERT_PARAM(p), C.uint64_t(v))
	if b == C.FALSE {
		return Error(C.GetLastError())
	}

	return nil
}

func CalcChecksums(buffer []byte, layer Layer, address *Address, flags uint64) error {
	//b := C.WinDivertHelperCalcChecksums(unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), C.WINDIVERT_LAYER(layer), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)), C.uint64_t(flags))
	b := C.WinDivertHelperCalcChecksums(unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)), C.uint64_t(flags))
	if b == 0 {
		return Error(C.GetLastError())
	}

	return nil
}
