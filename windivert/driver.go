package windivert

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func RemoveDriver() error {
	var versions = map[string]string{
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
