// +build windows

package filter

import (
	"fmt"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                   = windows.MustLoadDLL("kernel32.dll")
	queryFullProcessImageNameW = kernel32.MustFindProc("QueryFullProcessImageNameW")
)

// QueryFullProcessImageName is ...
func QueryFullProcessImageName(process windows.Handle, flags uint32, b []uint16) (string, error) {
	n := uint32(windows.MAX_PATH)

	// BOOL QueryFullProcessImageNameW(
	//   HANDLE hProcess,
	//   DWORD  dwFlags,
	//   LPSTR  lpExeName,
	//   PDWORD lpdwSize
	// );
	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
	ret, _, errno := queryFullProcessImageNameW.Call(
		uintptr(process),
		uintptr(flags),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(unsafe.Pointer(&n)),
	)
	if ret == 0 {
		return "", errno
	}
	return windows.UTF16ToString(b[:n]), nil
}

// QueryNameByPID is ...
func QueryNameByPID(id uint32, b []uint16) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, id)
	if err != nil {
		return "", fmt.Errorf("open process error: %w", err)
	}
	defer windows.CloseHandle(h)

	path, err := QueryFullProcessImageName(h, 0, b)
	if err != nil {
		return "", fmt.Errorf("query full process name error: %w", err)
	}

	_, file := filepath.Split(path)
	return file, nil
}

// AppFilter is ...
type AppFilter struct {
	// RWMutex is ...
	sync.RWMutex
	// PIDs is ...
	PIDs map[uint32]struct{}
	// Apps is ...
	Apps map[string]struct{}

	buff []uint16
}

// NewAppFilter is ...
func NewAppFilter() *AppFilter {
	f := &AppFilter{
		PIDs: make(map[uint32]struct{}),
		Apps: make(map[string]struct{}),
		buff: make([]uint16, windows.MAX_PATH),
	}
	return f
}

// SetPIDs is ...
func (f *AppFilter) SetPIDs(ids []uint32) {
	f.Lock()
	for _, v := range ids {
		f.PIDs[v] = struct{}{}
	}
	f.Unlock()
}

// Add is ...
func (f *AppFilter) Add(s string) {
	f.Lock()
	f.UnsafeAdd(s)
	f.Unlock()
}

// UnsafeAdd is ...
func (f *AppFilter) UnsafeAdd(s string) {
	f.Apps[s] = struct{}{}
}

// Lookup is ...
func (f *AppFilter) Lookup(id uint32) bool {
	f.RLock()
	defer f.RUnlock()

	// use PID
	if _, ok := f.PIDs[id]; ok {
		return true
	}

	// use name
	file, _ := QueryNameByPID(id, f.buff)

	_, ok := f.Apps[file]
	return ok
}
