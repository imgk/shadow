package windivert

// #cgo CFLAGS: -I${SRCDIR}/Divert/include
// #define WINDIVERTEXPORT static
// #include "Divert/dll/windivert.c"
// import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
	defer hd.Close()

	major, err := hd.GetParam(VersionMajor)
	if err != nil {
		panic(err)
	}

	minor, err := hd.GetParam(VersionMinor)
	if err != nil {
		panic(err)
	}

	if err := hd.Shutdown(ShutdownBoth); err != nil {
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
}

var (
	kernel32    = windows.NewLazySystemDLL("kernel32.dll")
	heapAlloc   = kernel32.NewProc("HeapAlloc")
	heapCreate  = kernel32.NewProc("HeapCreate")
	heapDestroy = kernel32.NewProc("HeapDestroy")
)

var (
	winDivert              = windows.NewLazySystemDLL("WinDivert.dll")
	winDivertOpen          = winDivert.NewProc("WinDivertOpen")
	winDivertRecv          = winDivert.NewProc("WinDivertRecv")
	winDivertRecvEx        = winDivert.NewProc("WinDivertRecvEx")
	winDivertSend          = winDivert.NewProc("WinDivertSend")
	winDivertSendEx        = winDivert.NewProc("WinDivertSendEx")
	winDivertShutdown      = winDivert.NewProc("WinDivertShutdown")
	winDivertClose         = winDivert.NewProc("WinDivertClose")
	winDivertSetParam      = winDivert.NewProc("WinDivertSetParam")
	winDivertGetParam      = winDivert.NewProc("WinDivertGetParam")
	winDivertCompileFilter = winDivert.NewProc("WinDivertCompileFilter")
	winDivertAnalyzeFilter = winDivert.NewProc("WinDivertAnalyzeFilter")
)

const (
	HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
	HEAP_GENERATE_EXCEPTIONS   = 0x00000004
	HEAP_NO_SERIALIZE          = 0x00000001
)

func HeapAlloc(hHeap windows.Handle, dwFlags, dwBytes uint32) (unsafe.Pointer, error) {
	ret, _, errno := heapAlloc.Call(uintptr(hHeap), uintptr(dwFlags), uintptr(dwBytes))
	if ret == 0 {
		return nil, errno
	}

	return unsafe.Pointer(ret), nil
}

func HeapCreate(flOptions, dwInitialSize, dwMaximumSize uint32) (windows.Handle, error) {
	ret, _, errno := heapCreate.Call(uintptr(flOptions), uintptr(dwInitialSize), uintptr(dwMaximumSize))
	if ret == 0 {
		return windows.InvalidHandle, errno
	}

	return windows.Handle(ret), nil
}

func HeapDestroy(hHeap windows.Handle) error {
	ret, _, errno := heapDestroy.Call(uintptr(hHeap))
	if ret == 0 {
		return errno
	}

	return nil
}

type filter struct {
	b1 uint32
	b2 uint32
	b3 [4]uint32
}

type version struct {
	magic uint64
	major uint32
	minor uint32
	bits  uint32
	_     [3]uint32
	_     [4]uint64
}

type FilterError int

func (e FilterError) Error() string {
	switch int(e) {
	case 0:
		return "WINDIVERT_ERROR_NONE"
	case 1:
		return "WINDIVERT_ERROR_NO_MEMORY"
	case 2:
		return "WINDIVERT_ERROR_TOO_DEEP"
	case 3:
		return "WINDIVERT_ERROR_TOO_LONG"
	case 4:
		return "WINDIVERT_ERROR_BAD_TOKEN"
	case 5:
		return "WINDIVERT_ERROR_BAD_TOKEN_FOR_LAYER"
	case 6:
		return "WINDIVERT_ERROR_UNEXPECTED_TOKEN"
	case 7:
		return "WINDIVERT_ERROR_INDEX_OOB"
	case 8:
		return "WINDIVERT_ERROR_OUTPUT_TOO_SHORT"
	case 9:
		return "WINDIVERT_ERROR_BAD_OBJECT"
	case 10:
		return "WINDIVERT_ERROR_ASSERTION_FAILED"
	default:
		return ""
	}
}

func CompileFilter(filter string, pool windows.Handle, layer Layer, object *filter) (uint, error) {
	filterPtr, err := windows.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}

	objLen := uint(0)

	ret, _, _ := winDivertCompileFilter.Call(uintptr(unsafe.Pointer(filterPtr)), uintptr(pool), uintptr(layer), uintptr(unsafe.Pointer(object)), uintptr(unsafe.Pointer(&objLen)))
	if ret != 0 {
		return 0, FilterError(ret >> 32)
	}

	return objLen, nil
}

func AnalyzeFilter(layer Layer, object *filter, objLen uint) uint64 {
	ret, _, _ := winDivertAnalyzeFilter.Call(uintptr(layer), uintptr(unsafe.Pointer(object)), uintptr(objLen))
	return uint64(ret)
}

func IoControlEx(h windows.Handle, code CtlCode, ioctl unsafe.Pointer, buf *byte, bufLen uint32, overlapped *windows.Overlapped) (iolen uint32, err error) {
	err = windows.DeviceIoControl(h, uint32(code), (*byte)(ioctl), uint32(unsafe.Sizeof(IoCtl{})), buf, bufLen, &iolen, overlapped)
	if err != windows.ERROR_IO_PENDING {
		return
	}

	err = windows.GetOverlappedResult(h, overlapped, &iolen, true)

	return
}

func IoControl(h windows.Handle, code CtlCode, ioctl unsafe.Pointer, buf *byte, bufLen uint32) (iolen uint32, err error) {
	event, _ := windows.CreateEvent(nil, 0, 0, nil)

	overlapped := windows.Overlapped{
		HEvent: event,
	}

	iolen, err = IoControlEx(h, code, ioctl, buf, bufLen, &overlapped)

	windows.CloseHandle(event)
	return
}

type Handle struct {
	sync.Mutex
	windows.Handle
	rOverlapped windows.Overlapped
	wOverlapped windows.Overlapped
}

func Open(filter string, layer Layer, priority int16, flags uint64) (*Handle, error) {
	if priority < PriorityLowest || priority > PriorityHighest {
		return nil, fmt.Errorf("Priority %v is not Correct, Max: %v, Min: %v", priority, PriorityHighest, PriorityLowest)
	}

	filterPtr, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	runtime.LockOSThread()
	hd, _, err := winDivertOpen.Call(uintptr(unsafe.Pointer(filterPtr)), uintptr(layer), uintptr(priority), uintptr(flags))
	runtime.UnlockOSThread()

	if windows.Handle(hd) == windows.InvalidHandle {
		return nil, Error(err.(syscall.Errno))
	}

	//hd := C.WinDivertOpen(C.CString(filter), C.WINDIVERT_LAYER(layer), C.int16_t(priority), C.uint64_t(flags))
	//if windows.Handle(hd) == windows.InvalidHandle {
	//	return nil, Error(C.GetLastError())
	//}

	rEvent, _ := windows.CreateEvent(nil, 0, 0, nil)
	wEvent, _ := windows.CreateEvent(nil, 0, 0, nil)

	return &Handle{
		Mutex:  sync.Mutex{},
		Handle: windows.Handle(hd),
		rOverlapped: windows.Overlapped{
			HEvent: rEvent,
		},
		wOverlapped: windows.Overlapped{
			HEvent: wEvent,
		},
	}, nil
}

func (h Handle) Recv(buffer []byte, address *Address) (uint, error) {
	addrLen := uint(unsafe.Sizeof(Address{}))
	recv := recv{
		Addr:       uint64(uintptr(unsafe.Pointer(address))),
		AddrLenPtr: uint64(uintptr(unsafe.Pointer(&addrLen))),
	}

	iolen, err := IoControlEx(h.Handle, IoCtlRecv, unsafe.Pointer(&recv), &buffer[0], uint32(len(buffer)), &h.rOverlapped)
	if err != nil {
		return uint(iolen), Error(err.(syscall.Errno))
	}

	return uint(iolen), nil

	//recvLen := uint(0)
	//b := C.WinDivertRecv(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&recvLen)), C.PWINDIVERT_ADDRESS(unsafe.Pointer(address)))
	//if b == C.FALSE {
	//	return 0, Error(C.GetLastError())
	//}

	//return recvLen, nil
}

func (h *Handle) RecvEx(buffer []byte, address []Address, overlapped *windows.Overlapped) (uint, uint, error) {
	addrLen := uint(len(address)) * uint(unsafe.Sizeof(Address{}))
	recv := recv{
		Addr:       uint64(uintptr(unsafe.Pointer(&address[0]))),
		AddrLenPtr: uint64(uintptr(unsafe.Pointer(&addrLen))),
	}

	iolen, err := IoControlEx(h.Handle, IoCtlRecv, unsafe.Pointer(&recv), &buffer[0], uint32(len(buffer)), &h.rOverlapped)
	if err != nil {
		return uint(iolen), addrLen / uint(unsafe.Sizeof(Address{})), Error(err.(syscall.Errno))
	}

	return uint(iolen), addrLen / uint(unsafe.Sizeof(Address{})), nil

	//recvLen := uint(0)

	//addrLen := uint(len(address)) * uint(unsafe.Sizeof(C.WINDIVERT_ADDRESS{}))
	//b := C.WinDivertRecvEx(C.HANDLE(h), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&recvLen)), C.uint64_t(0), C.PWINDIVERT_ADDRESS(unsafe.Pointer(&address[0])), (*C.uint)(unsafe.Pointer(&addrLen)), C.LPOVERLAPPED(unsafe.Pointer(overlapped)))
	//if b == C.FALSE {
	//	return 0, 0, GetLastError()
	//}
	//addrLen /= uint(unsafe.Sizeof(C.WINDIVERT_ADDRESS{}))

	//return recvLen, addrLen, nil
}

func (h *Handle) Send(buffer []byte, address *Address) (uint, error) {
	send := send{
		Addr:    uint64(uintptr(unsafe.Pointer(address))),
		AddrLen: uint64(unsafe.Sizeof(Address{})),
	}

	iolen, err := IoControlEx(h.Handle, IoCtlSend, unsafe.Pointer(&send), &buffer[0], uint32(len(buffer)), &h.wOverlapped)
	if err != nil {
		return uint(iolen), Error(err.(syscall.Errno))
	}

	return uint(iolen), nil

	//sendLen := uint(0)
	//b := C.WinDivertSend(C.HANDLE(h.Handle), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&sendLen)), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)))
	//if b == C.FALSE {
	//	return 0, Error(C.GetLastError())
	//}

	//return sendLen, nil
}

func (h *Handle) SendEx(buffer []byte, address []Address, overlapped *windows.Overlapped) (uint, error) {
	send := send{
		Addr:    uint64(uintptr(unsafe.Pointer(&address[0]))),
		AddrLen: uint64(unsafe.Sizeof(Address{})) * uint64(len(address)),
	}

	iolen, err := IoControlEx(h.Handle, IoCtlSend, unsafe.Pointer(&send), &buffer[0], uint32(len(buffer)), &h.wOverlapped)
	if err != nil {
		return uint(iolen), Error(err.(syscall.Errno))
	}

	return uint(iolen), nil

	//sendLen := uint(0)

	//b := C.WinDivertSendEx(C.HANDLE(h), unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.uint)(unsafe.Pointer(&sendLen)), C.uint64_t(0), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(&address[0])), C.uint(uint(len(address))*uint(unsafe.Sizeof(C.WINDIVERT_ADDRESS{}))), C.LPOVERLAPPED(unsafe.Pointer(overlapped)))
	//if b == C.FALSE {
	//	return 0, GetLastError()
	//}

	//return sendLen, nil
}

func (h *Handle) Shutdown(how Shutdown) error {
	shutdown := shutdown{
		How: uint32(how),
	}

	_, err := IoControl(h.Handle, IoCtlShutdown, unsafe.Pointer(&shutdown), nil, 0)
	if err != nil {
		return Error(err.(syscall.Errno))
	}

	return nil

	//b := C.WinDivertShutdown(C.HANDLE(h.Handle), C.WINDIVERT_SHUTDOWN(how))
	//if b == C.FALSE {
	//	return Error(C.GetLastError())
	//}

	//return nil
}

func (h *Handle) Close() error {
	windows.CloseHandle(h.rOverlapped.HEvent)
	windows.CloseHandle(h.wOverlapped.HEvent)

	err := windows.CloseHandle(h.Handle)
	if err != nil {
		return Error(err.(syscall.Errno))
	}

	return nil

	//b := C.WinDivertClose(C.HANDLE(h.Handle))
	//if b == C.FALSE {
	//	return Error(C.GetLastError())
	//}

	//return nil
}

func (h *Handle) GetParam(p Param) (uint64, error) {
	getParam := getParam{
		Param: uint32(p),
		Value: 0,
	}

	_, err := IoControl(h.Handle, IoCtlGetParam, unsafe.Pointer(&getParam), (*byte)(unsafe.Pointer(&getParam.Value)), uint32(unsafe.Sizeof(getParam.Value)))
	if err != nil {
		return getParam.Value, Error(err.(syscall.Errno))
	}

	return getParam.Value, nil

	//v := uint64(0)

	//b := C.WinDivertGetParam(C.HANDLE(h.Handle), C.WINDIVERT_PARAM(p), (*C.uint64_t)(unsafe.Pointer(&v)))
	//if b == C.FALSE {
	//	return v, Error(C.GetLastError())
	//}

	//return v, nil
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

	setParam := setParam{
		Value: v,
		Param: uint32(p),
	}

	_, err := IoControl(h.Handle, IoCtlSetParam, unsafe.Pointer(&setParam), nil, 0)
	if err != nil {
		return Error(err.(syscall.Errno))
	}

	return nil

	//b := C.WinDivertSetParam(C.HANDLE(h.Handle), C.WINDIVERT_PARAM(p), C.uint64_t(v))
	//if b == C.FALSE {
	//	return Error(C.GetLastError())
	//}

	//return nil
}

func CalcChecksums(buffer []byte, layer Layer, address *Address, flags uint64) error {
	return CalcChecksumsEx(buffer, layer, address, flags)

	//b := C.WinDivertHelperCalcChecksums(unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), C.WINDIVERT_LAYER(layer), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)), C.uint64_t(flags))
	//b := C.WinDivertHelperCalcChecksums(unsafe.Pointer(&buffer[0]), C.uint(len(buffer)), (*C.WINDIVERT_ADDRESS)(unsafe.Pointer(address)), C.uint64_t(flags))
	//if b == 0 {
	//	return Error(C.GetLastError())
	//}

	//return nil
}
