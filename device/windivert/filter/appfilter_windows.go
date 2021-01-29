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

func QueryFullProcessImageName(process windows.Handle, flags uint32) (s string, err error) {
	b := make([]uint16, windows.MAX_PATH)
	n := uint32(windows.MAX_PATH)

	// BOOL QueryFullProcessImageNameA(
	//   HANDLE hProcess,
	//   DWORD  dwFlags,
	//   LPSTR  lpExeName,
	//   PDWORD lpdwSize
	// );
	// https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
	ret, _, errno := queryFullProcessImageNameW.Call(
		uintptr(process),
		uintptr(flags),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(unsafe.Pointer(&n)),
	)
	if ret == 0 {
		err = errno
	}
	if err == nil {
		s = windows.UTF16ToString(b[:n])
	}
	return
}

func QueryNameByPID(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("open process error: %w", err)
	}
	defer windows.CloseHandle(h)

	path, err := QueryFullProcessImageName(h, 0)
	if err != nil {
		return "", fmt.Errorf("query full process name error: %w", err)
	}

	_, file := filepath.Split(path)
	return file, nil
}

type AppFilter struct {
	sync.RWMutex
	pids map[uint32]struct{}
	apps map[string]struct{}
}

func NewAppFilter() *AppFilter {
	f := &AppFilter{
		RWMutex: sync.RWMutex{},
		pids:    make(map[uint32]struct{}),
		apps:    make(map[string]struct{}),
	}
	return f
}

func (f *AppFilter) SetPIDs(pids []uint32) {
	f.Lock()
	for _, v := range pids {
		f.pids[v] = struct{}{}
	}
	f.Unlock()
}

func (f *AppFilter) Add(s string) {
	f.Lock()
	f.UnsafeAdd(s)
	f.Unlock()
}

func (f *AppFilter) UnsafeAdd(s string) {
	f.apps[s] = struct{}{}
}

func (f *AppFilter) Lookup(pid uint32) bool {
	f.RLock()
	defer f.RUnlock()

	if _, ok := f.pids[pid]; ok {
		return true
	}

	file, _ := QueryNameByPID(pid)
	if _, ok := f.apps[file]; ok {
		return true
	}

	return false
}
