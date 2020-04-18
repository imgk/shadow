package windivert

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

func TryRemoveDriver() error {
	b, err := Check()
	if err != nil {
		return fmt.Errorf("check process using windivert error: %v", err)
	}

	if b {
		if err := RemoveDriver(); err != nil {
			return fmt.Errorf("remove windivert error: %v", err)
		}
	}

	return nil
}

func Check() (bool, error) {
	hd, err := Open("true", LayerReflect, 777, FlagSniff|FlagRecvOnly|FlagNoInstall)
	if err != nil {
		return false, err
	}
	defer hd.Close()

	if err := hd.Shutdown(ShutdownBoth); err != nil {
		return false, err
	}

	id := windows.GetCurrentProcessId()

	a := new(Address)
	b := make([]byte, 1500)

	for {
		_, err := hd.Recv(b, a)
		if err != nil {
			if err == ErrNoData {
				return true, nil
			}

			if err == ErrInsufficientBuffer {
				return false, nil
			}

			return false, err
		}

		rt := a.Reflect()
		if rt.ProcessID != id {
			return false, nil
		}
	}
}

func RemoveDriver() error {
	var versions = map[string]string{
		"1.0": "WinDivert1.0",
		"1.1": "WinDivert1.1",
		"1.2": "WinDivert1.2",
		"1.3": "WinDivert1.3",
		"1.4": "WinDivert1.4",
		"2.0": "WinDivert",
		"2.1": "WinDivert",
		"2.2": "WinDivert",
	}

	status := windows.SERVICE_STATUS{}
	vers := versions[Version()]

	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)

	service, err := windows.OpenService(manager, windows.StringToUTF16Ptr(vers), windows.SERVICE_ALL_ACCESS)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == windows.ERROR_SERVICE_DOES_NOT_EXIST {
				return nil
			}
		}
		return err
	}
	defer windows.CloseServiceHandle(service)

	if err := windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &status); err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == windows.ERROR_SERVICE_NOT_ACTIVE {
				return nil
			}
		}
		return err
	}

	if err := windows.DeleteService(service); err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == windows.ERROR_SERVICE_MARKED_FOR_DELETE {
				return nil
			}
		}
		return err
	}

	if err := windows.CloseServiceHandle(service); err != nil {
		return err
	}

	return windows.CloseServiceHandle(manager)
}
