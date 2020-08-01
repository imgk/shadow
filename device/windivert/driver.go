package windivert

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const types = 7

func CloseMutex(mutex windows.Handle) {
	windows.ReleaseMutex(mutex)
	windows.CloseHandle(mutex)
}

func InstallDriver() error {
	mutex, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("WinDivertDriverInstallMutex"))
	if err != nil {
		return err
	}
	defer CloseMutex(mutex)

	event, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
	if err != nil {
		return err
	}
	switch event {
	case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
	default:
		return errors.New("wait for object error")
	}

	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)

	service, err := windows.OpenService(manager, DeviceName, windows.SERVICE_ALL_ACCESS)
	if err == nil {
		windows.CloseServiceHandle(service)
		return nil
	}

	sys, err := GetDriverFileName()
	if err != nil {
		return err
	}

	service, err = windows.CreateService(manager, DeviceName, DeviceName, windows.SERVICE_ALL_ACCESS, windows.SERVICE_KERNEL_DRIVER, windows.SERVICE_DEMAND_START, windows.SERVICE_ERROR_NORMAL, windows.StringToUTF16Ptr(sys), nil, nil, nil, nil, nil)
	if err != nil {
		if err == windows.ERROR_SERVICE_EXISTS {
			return nil
		}

		service, err = windows.OpenService(manager, DeviceName, windows.SERVICE_ALL_ACCESS)
		if err != nil {
			return err
		}
	}
	defer windows.CloseServiceHandle(service)

	if err := windows.StartService(service, 0, nil); err != nil && err != windows.ERROR_SERVICE_ALREADY_RUNNING {
		return err
	}

	if err := windows.DeleteService(service); err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
		return err
	}

	return nil
}

func RemoveDriver() error {
	status := windows.SERVICE_STATUS{}

	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)

	service, err := windows.OpenService(manager, DeviceName, windows.SERVICE_ALL_ACCESS)
	if err != nil {
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return nil
		}

		return err
	}
	defer windows.CloseServiceHandle(service)

	if err := windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &status); err != nil {
		if err == windows.ERROR_SERVICE_NOT_ACTIVE {
			return nil
		}

		return err
	}

	if err := windows.DeleteService(service); err != nil {
		if err == windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			return nil
		}

		return err
	}

	return nil
}

func GetDriverFileName() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\EventLog\\System\\WinDivert", registry.QUERY_VALUE)
	if err != nil {
		if _, err := os.Stat(windivertsys); err != nil {
			if er := Download(); er != nil {
				return "", fmt.Errorf("file error: %w, download error: %w", err, er)
			}
		}

		if err := RegisterEventSource(windivertsys); err != nil {
			return "", err
		}

		return windivertsys, nil
	}
	defer key.Close()

	val, _, err := key.GetStringValue("EventMessageFile")
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(val); err != nil {
		if _, err := os.Stat(windivertsys); err != nil {
			if er := Download(); er != nil {
				return "", fmt.Errorf("file error: %w, download error: %w", err, er)
			}
		}

		if err := RegisterEventSource(windivertsys); err != nil {
			return "", err
		}

		return windivertsys, nil
	}

	return val, nil
}

func RegisterEventSource(sys string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\EventLog\\System\\WinDivert", registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	if err := key.SetStringValue("EventMessageFile", sys); err != nil {
		return err
	}

	if err := key.SetDWordValue("TypesSupported", types); err != nil {
		return err
	}

	return nil
}
