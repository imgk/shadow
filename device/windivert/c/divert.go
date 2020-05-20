package c

// #cgo CFLAGS: -I${SRCDIR}/Divert/include
// #define WINDIVERTEXPORT static
// #include "Divert/dll/windivert.c"
import "C"

import (
	"golang.org/x/sys/windows"
)

func Open(filter string, layer int, priority int16, flags uint64) (windows.Handle, error) {
	hd := C.WinDivertOpen(C.CString(filter), C.WINDIVERT_LAYER(layer), C.int16_t(priority), C.uint64_t(flags))
	if windows.Handle(hd) == windows.InvalidHandle {
		return windows.InvalidHandle, windows.Errno(C.GetLastError())
	}

	return windows.Handle(hd), nil
}
