package windivert

// #cgo CFLAGS: -I${SRCDIR}/Divert/include
// #include "windivert.h"
import "C"

import (
	"errors"
	"fmt"
)

var (
	ErrNoData             = errors.New("The handle has been shutdown using WinDivertShutdown() and the packet queue is empty")
	ErrIOPending          = errors.New("The error code ERROR_IO_PENDING indicates that the overlapped operation has been successfully initiated and that completion will be indicated at a later time")
	ErrInsufficientBuffer = errors.New("The captured packet is larger than the pPacket buffer")
)

func GetLastError() error {
	switch errno := C.GetLastError(); errno {
	case C.ERROR_FILE_NOT_FOUND:
		return errors.New("The driver files WinDivert32.sys or WinDivert64.sys were not found")
	case C.ERROR_ACCESS_DENIED:
		return errors.New("The calling application does not have Administrator privileges")
	case C.ERROR_INVALID_PARAMETER:
		return errors.New("This indicates an invalid packet filter string, layer, priority, or flags")
	case 577: // C.ERROR_INVALID_IMAGE_HASH
		return errors.New("The WinDivert32.sys or WinDivert64.sys driver does not have a valid digital signature (see the driver signing requirements above)")
	case 654: // C.ERROR_DRIVER_FAILED_PRIOR_UNLOAD
		return errors.New("An incompatible version of the WinDivert driver is currently loaded")
	case C.ERROR_SERVICE_DOES_NOT_EXIST:
		return errors.New("The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag and the WinDivert driver is not already installed")
	case C.ERROR_DRIVER_BLOCKED:
		return errors.New("This error occurs for various reasons, including: the WinDivert driver is blocked by security software; or you are using a virtualization environment that does not support drivers")
	case C.ERROR_INSUFFICIENT_BUFFER:
		return ErrInsufficientBuffer
	case C.ERROR_NO_DATA:
		return ErrNoData
	case C.ERROR_IO_PENDING:
		return ErrIOPending
	case C.ERROR_HOST_UNREACHABLE:
		return errors.New("This error occurs when an impostor packet (with pAddr->Impostor set to 1) is injected and the ip.TTL or ipv6.HopLimit field goes to zero. This is a defense of \"last resort\" against infinite loops caused by impostor packets")
	case C.EPT_S_NOT_REGISTERED:
		return errors.New("This error occurs when the Base Filtering Engine service has been disabled")
	default:
		return fmt.Errorf("windivert error errno: %v", errno)
	}
}
