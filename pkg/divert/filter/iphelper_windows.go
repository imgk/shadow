// +build windows

package filter

import (
	"errors"
	"net"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.MustLoadDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.MustFindProc("GetExtendedTcpTable")
	getExtendedUdpTable = iphlpapi.MustFindProc("GetExtendedUdpTable")
	getBestInterfaceEx  = iphlpapi.MustFindProc("GetBestInterfaceEx")
)

// GetTCPTable is ...
func GetTCPTable(buf []byte) ([]TCPRow, error) {
	b, err := GetExtendedTcpTable(0, windows.AF_INET, 4 /* TCP_TABLE_OWNER_PID_CONNECTIONS */, buf)
	if err != nil {
		return nil, err
	}
	t := (*TCPTable)(unsafe.Pointer(&b[0]))
	h := &reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&t.Table)),
		Len:  int(t.Len),
		Cap:  int(t.Len),
	}
	return *(*[]TCPRow)(unsafe.Pointer(h)), nil
}

// TCPTable is ...
type TCPTable struct {
	Len   uint32
	Table [1]TCPRow
}

// TCPRow is ...
type TCPRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// GetTCP6Table is ...
func GetTCP6Table(buf []byte) ([]TCP6Row, error) {
	b, err := GetExtendedTcpTable(0, windows.AF_INET6, 4 /* TCP_TABLE_OWNER_PID_CONNECTIONS */, buf)
	if err != nil {
		return nil, err
	}
	t := (*TCP6Table)(unsafe.Pointer(&b[0]))
	h := &reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&t.Table)),
		Len:  int(t.Len),
		Cap:  int(t.Len),
	}
	return *(*[]TCP6Row)(unsafe.Pointer(h)), nil
}

// TCP6Table is ...
type TCP6Table struct {
	Len   uint32
	Table [1]TCP6Row
}

// TCP6Row is ...
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

// GetExtendedTcpTable is ...
func GetExtendedTcpTable(order uint32, ulAf uint32, tableClass uint32, buf []byte) ([]byte, error) {
	pTcpTable := &buf[0]
	dwSize := uint32(len(buf))

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
		if ret == windows.NO_ERROR {
			return buf, nil
		}
		if windows.Errno(ret) == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]byte, dwSize)
			pTcpTable = &buf[0]
			continue
		}
		return nil, errno
	}
}

// GetUDPTable is ...
func GetUDPTable(buf []byte) ([]UDPRow, error) {
	b, err := GetExtendedUdpTable(0, windows.AF_INET, 1 /* UDP_TABLE_OWNER_PID */, buf)
	if err != nil {
		return nil, err
	}
	t := (*UDPTable)(unsafe.Pointer(&b[0]))
	h := &reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&t.Table)),
		Len:  int(t.Len),
		Cap:  int(t.Len),
	}
	return *(*[]UDPRow)(unsafe.Pointer(h)), nil
}

// UDPTable is ...
type UDPTable struct {
	Len   uint32
	Table [1]UDPRow
}

// UDPRow is ...
type UDPRow struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// GetUDP6Table is ...
func GetUDP6Table(buf []byte) ([]UDP6Row, error) {
	b, err := GetExtendedUdpTable(0, windows.AF_INET6, 1 /* UDP_TABLE_OWNER_PID */, buf)
	if err != nil {
		return nil, err
	}
	t := (*UDP6Table)(unsafe.Pointer(&b[0]))
	h := &reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&t.Table)),
		Len:  int(t.Len),
		Cap:  int(t.Len),
	}
	return *(*[]UDP6Row)(unsafe.Pointer(h)), nil
}

// UDP6Table is ...
type UDP6Table struct {
	Len   uint32
	Table [1]UDP6Row
}

// UDP6Row is ...
type UDP6Row struct {
	LocalAddr    [4]uint32
	LocalScopeId uint32
	LocalPort    uint32
	OwningPid    uint32
}

// GetExtendedUdpTable is ...
func GetExtendedUdpTable(order uint32, ulAf uint32, tableClass uint32, buf []byte) ([]byte, error) {
	pUdpTable := &buf[0]
	dwSize := uint32(len(buf))

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
		if ret == windows.NO_ERROR {
			return buf, nil
		}
		if windows.Errno(ret) == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]byte, dwSize)
			pUdpTable = &buf[0]
			continue
		}
		return nil, errno
	}
}

// GetInterfaceIndex is ...
func GetInterfaceIndex(s string) (int, error) {
	destAddr := windows.RawSockaddr{}

	ip := net.ParseIP(s)
	if ip == nil {
		return 0, errors.New("parse ip error")
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		addr := (*windows.RawSockaddrInet4)(unsafe.Pointer(&destAddr))
		addr.Family = windows.AF_INET
		copy(addr.Addr[:], ipv4)
	} else {
		ipv6 := ip.To16()
		addr := (*windows.RawSockaddrInet6)(unsafe.Pointer(&destAddr))
		addr.Family = windows.AF_INET6
		copy(addr.Addr[:], ipv6)
	}

	return GetBestInterfaceEx(&destAddr)
}

// GetBestInterfaceEx is ...
func GetBestInterfaceEx(addr *windows.RawSockaddr) (int, error) {
	dwBestIfIndex := int32(0)

	// IPHLPAPI_DLL_LINKAGE DWORD GetBestInterfaceEx(
	//  sockaddr *pDestAddr,
	//  PDWORD   pdwBestIfIndex
	// );
	// https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterfaceex
	ret, _, errno := getBestInterfaceEx.Call(
		uintptr(unsafe.Pointer(addr)),
		uintptr(unsafe.Pointer(&dwBestIfIndex)),
	)
	if ret == windows.NO_ERROR {
		return int(dwBestIfIndex), nil
	}
	return 0, errno
}
