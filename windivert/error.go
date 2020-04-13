package windivert

// #cgo CFLAGS: -I${SRCDIR}/Divert/include
// #include "windivert.h"
import "C"

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	ErrNoData             = errors.New("The handle has been shutdown using WinDivertShutdown() and the packet queue is empty")
	ErrIOPending          = errors.New("The error code ERROR_IO_PENDING indicates that the overlapped operation has been successfully initiated and that completion will be indicated at a later time")
	ErrInsufficientBuffer = errors.New("The captured packet is larger than the pPacket buffer")
	ErrHostUnreachable    = errors.New("This error occurs when an impostor packet (with pAddr->Impostor set to 1) is injected and the ip.TTL or ipv6.HopLimit field goes to zero. This is a defense of \"last resort\" against infinite loops caused by impostor packets")
)

func GetLastError() error {
	switch errno := syscall.Errno(C.GetLastError()); errno {
	case windows.ERROR_SUCCESS:
		return nil
	case windows.ERROR_FILE_NOT_FOUND:
		return errors.New("The driver files WinDivert32.sys or WinDivert64.sys were not found")
	case windows.ERROR_ACCESS_DENIED:
		return errors.New("The calling application does not have Administrator privileges")
	case windows.ERROR_INVALID_PARAMETER:
		return errors.New("This indicates an invalid packet filter string, layer, priority, or flags")
	case windows.ERROR_INVALID_IMAGE_HASH:
		return errors.New("The WinDivert32.sys or WinDivert64.sys driver does not have a valid digital signature (see the driver signing requirements above)")
	case windows.ERROR_DRIVER_FAILED_PRIOR_UNLOAD:
		return errors.New("An incompatible version of the WinDivert driver is currently loaded")
	case windows.ERROR_SERVICE_DOES_NOT_EXIST:
		return errors.New("The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag and the WinDivert driver is not already installed")
	case windows.ERROR_DRIVER_BLOCKED:
		return errors.New("This error occurs for various reasons, including: the WinDivert driver is blocked by security software; or you are using a virtualization environment that does not support drivers")
	case windows.ERROR_INSUFFICIENT_BUFFER:
		return ErrInsufficientBuffer
	case windows.ERROR_NO_DATA:
		return ErrNoData
	case windows.ERROR_IO_PENDING:
		return ErrIOPending
	case windows.ERROR_HOST_UNREACHABLE:
		return ErrHostUnreachable
	case windows.EPT_S_NOT_REGISTERED:
		return errors.New("This error occurs when the Base Filtering Engine service has been disabled")
	case windows.ERROR_OPERATION_ABORTED:
		return errors.New("The I/O operation has been aborted because of either a thread exit or an application request.")
	case windows.ERROR_INVALID_HANDLE:
		return errors.New("The handle is invalid.")
	default:
		return fmt.Errorf("windivert error: %v", errno)
	}
}
