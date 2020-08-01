// +build windows

package utils

import (
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	TCP_TABLE_OWNER_PID_LISTENER       = 3
	TCP_TABLE_OWNER_PID_CONNECTIONS    = 4
	TCP_TABLE_OWNER_PID_ALL            = 5
	TCP_TABLE_OWNER_MODULE_LISTENER    = 6
	TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7
	TCP_TABLE_OWNER_MODULE_ALL         = 8

	UDP_TABLE_OWNER_PID    = 1
	UDP_TABLE_OWNER_MODULE = 2
)

var (
	iphlpapi            = windows.MustLoadDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.MustFindProc("GetExtendedTcpTable")
	getExtendedUdpTable = iphlpapi.MustFindProc("GetExtendedUdpTable")
)

func GetTCPTable() ([]TCPRow, error) {
	b, err := GetExtendedTcpTable(0, windows.AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS)
	if err != nil {
		return nil, err
	}

	t := (*TCPTable)(unsafe.Pointer(&b[0]))

	h := &reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&t.table)),
		Len:  int(t.n),
		Cap:  int(t.n),
	}

	return *(*[]TCPRow)(unsafe.Pointer(h)), nil
}

type TCPTable struct {
	n     uint32
	table [1]TCPRow
}

type TCPRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

func GetTCP6Table() ([]TCP6Row, error) {
	b, err := GetExtendedTcpTable(0, windows.AF_INET6, TCP_TABLE_OWNER_PID_CONNECTIONS)
	if err != nil {
		return nil, err
	}

	t := (*TCP6Table)(unsafe.Pointer(&b[0]))

	h := &reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&t.table)),
		Len:  int(t.n),
		Cap:  int(t.n),
	}

	return *(*[]TCP6Row)(unsafe.Pointer(h)), nil
}

type TCP6Table struct {
	n     uint32
	table [1]TCP6Row
}

type TCP6Row struct {
	LocalAddr     [4]uint32
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [4]uint32
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

func GetExtendedTcpTable(order uint32, ulAf uint32, tableClass uint32) ([]byte, error) {
	var buffer []byte
	var pTcpTable *byte
	var dwSize uint32

	for {
		// DWORD GetExtendedTcpTable(
		//  PVOID           pTcpTable,
		//  PDWORD          pdwSize,
		//  BOOL            bOrder,
		//  ULONG           ulAf,
		//  TCP_TABLE_CLASS TableClass,
		//  ULONG           Reserved
		// );
		// https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
		ret, _, errno := getExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(pTcpTable)),
			uintptr(unsafe.Pointer(&dwSize)),
			uintptr(order),
			uintptr(ulAf),
			uintptr(tableClass),
			uintptr(uint32(0)),
		)

		if ret != windows.NO_ERROR {
			if windows.Errno(ret) == windows.ERROR_INSUFFICIENT_BUFFER {
				buffer = make([]byte, dwSize)
				pTcpTable = &buffer[0]
				continue
			}

			return nil, errno
		}

		return buffer, nil
	}
}

func GetUDPTable() ([]UDPRow, error) {
	b, err := GetExtendedUdpTable(0, windows.AF_INET, UDP_TABLE_OWNER_PID)
	if err != nil {
		return nil, err
	}

	t := (*UDPTable)(unsafe.Pointer(&b[0]))

	h := &reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&t.table)),
		Len:  int(t.n),
		Cap:  int(t.n),
	}

	return *(*[]UDPRow)(unsafe.Pointer(h)), nil
}

type UDPTable struct {
	n     uint32
	table [1]UDPRow
}

type UDPRow struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

func GetUDP6Table() ([]UDP6Row, error) {
	b, err := GetExtendedUdpTable(0, windows.AF_INET6, UDP_TABLE_OWNER_PID)
	if err != nil {
		return nil, err
	}

	t := (*UDP6Table)(unsafe.Pointer(&b[0]))

	h := &reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&t.table)),
		Len:  int(t.n),
		Cap:  int(t.n),
	}

	return *(*[]UDP6Row)(unsafe.Pointer(h)), nil
}

type UDP6Table struct {
	n     uint32
	table [1]UDP6Row
}

type UDP6Row struct {
	LocalAddr    [4]uint32
	LocalScopeId uint32
	LocalPort    uint32
	OwningPid    uint32
}

func GetExtendedUdpTable(order uint32, ulAf uint32, tableClass uint32) ([]byte, error) {
	var buffer []byte
	var pUdpTable *byte
	var dwSize uint32

	for {
		// DWORD GetExtendedUdpTable(
		//  PVOID           pUdpTable,
		//  PDWORD          pdwSize,
		//  BOOL            bOrder,
		//  ULONG           ulAf,
		//  UDP_TABLE_CLASS TableClass,
		//  ULONG           Reserved
		// );
		// https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
		ret, _, errno := getExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(pUdpTable)),
			uintptr(unsafe.Pointer(&dwSize)),
			uintptr(order),
			uintptr(ulAf),
			uintptr(tableClass),
			uintptr(uint32(0)),
		)

		if ret != windows.NO_ERROR {
			if windows.Errno(ret) == windows.ERROR_INSUFFICIENT_BUFFER {
				buffer = make([]byte, dwSize)
				pUdpTable = &buffer[0]
				continue
			}

			return nil, errno
		}

		return buffer, nil
	}
}
