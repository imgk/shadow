// +build windows

package utils

import (
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	queryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW").Addr()
)

var buffer = sync.Pool{New: func() interface{} { return make([]uint16, windows.MAX_LONG_PATH) }}

func QueryFullProcessImageName(process windows.Handle, flags uint32) (s string, err error) {
	b := buffer.Get().([]uint16)
	defer buffer.Put(b)

	l := uint32(len(b))

	r1, _, e1 := syscall.Syscall6(
		queryFullProcessImageNameW,
		4,
		uintptr(process),
		uintptr(flags),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(unsafe.Pointer(&l)),
		0,
		0,
	)
	if r1 == 0 {
		if e1 != 0 {
			err = e1
		} else {
			err = syscall.EINVAL
		}
	}
	if err == nil {
		s = windows.UTF16ToString(b[:l])
	}
	return
}

func QueryName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("open process error: %v", err)
	}
	defer windows.CloseHandle(h)

	path, err := QueryFullProcessImageName(h, 0)
	if err != nil {
		return "", fmt.Errorf("query full process name error: %v", err)
	}

	_, file := filepath.Split(path)

	return file, nil
}

type AppFilter struct {
	sync.RWMutex
	apps map[string]struct{}
}

func NewAppFilter() *AppFilter {
	f := &AppFilter{
		RWMutex: sync.RWMutex{},
		apps:    make(map[string]struct{}),
	}

	return f
}

func (f *AppFilter) String() string {
	s := "Programs:"
	for k, _ := range f.apps {
		s += fmt.Sprintf("\t%v\n", k)
	}

	return s
}

func (f *AppFilter) Reset() {
	f.Lock()
	defer f.Unlock()

	f.UnsafeReset()
}

func (f *AppFilter) UnsafeReset() {
	f.apps = make(map[string]struct{})
}

func (f *AppFilter) Add(s string) {
	f.Lock()
	defer f.Unlock()

	f.UnsafeAdd(s)
}

func (f *AppFilter) UnsafeAdd(s string) {
	f.apps[s] = struct{}{}
}

func (f *AppFilter) Lookup(pid uint32) bool {
	f.RLock()
	defer f.RUnlock()

	file, _ := QueryName(pid)
	if _, ok := f.apps[file]; ok {
		return true
	}

	return false
}
