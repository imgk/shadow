// +build windows,!wintun

package app

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"

	"github.com/imgk/shadow/device/windivert"
	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
	"github.com/imgk/shadow/utils"
)

func CloseMutex(mutex windows.Handle) {
	windows.ReleaseMutex(mutex)
	windows.CloseHandle(mutex)
}

func Run(opt Option) error {
	mutexName := windows.StringToUTF16Ptr("SHADOW-MUTEX")

	mutex, err := windows.OpenMutex(windows.MUTEX_ALL_ACCESS, false, mutexName)
	if err == nil {
		windows.CloseHandle(mutex)
		return fmt.Errorf("shadow is already running")
	}
	mutex, err = windows.CreateMutex(nil, false, mutexName)
	if err != nil {
		return fmt.Errorf("create mutex error: %w", err)
	}
	defer CloseMutex(mutex)

	event, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("wait for mutex error: %w", err)
	}
	switch event {
	case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
	default:
		return fmt.Errorf("wait for mutex event id error: %w", event)
	}

	resolver, err := utils.NewResolver(opt.Conf.NameServer)
	if err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     resolver.DialContext,
	}

	handler, err := protocol.NewHandler(opt.Conf.Server, opt.Timeout)
	if err != nil {
		return fmt.Errorf("protocol error %w", err)
	}

	dev, err := windivert.NewDevice(opt.Conf.FilterString)
	if err != nil {
		return fmt.Errorf("windivert error: %w", err)
	}

	stack := netstack.NewStack(handler, dev, resolver, opt.Writer)

RELOAD:
	for {
		loadAppRules(dev.AppFilter, opt.Conf.AppRules.Proxy)
		loadIPCIDRRules(dev.IPFilter, opt.Conf.IPCIDRRules.Proxy)
		loadDomainRules(stack.DomainTree, opt.Conf.DomainRules.Proxy, opt.Conf.DomainRules.Direct, opt.Conf.DomainRules.Blocked)
		opt.Conf.free()
		select {
		case <-opt.Ctx.Done():
			break RELOAD
		case <-opt.Reload:
			continue
		}
	}

	stack.Close()
	close(opt.Done)
	return nil
}

func loadIPCIDRRules(ipfilter *utils.IPFilter, cidr []string) {
	ipfilter.Lock()
	defer ipfilter.Unlock()

	ipfilter.UnsafeReset()
	for _, item := range cidr {
		ipfilter.UnsafeAdd(item)
	}
}

func loadAppRules(appfilter *utils.AppFilter, apps []string) {
	appfilter.Lock()
	defer appfilter.Unlock()

	appfilter.UnsafeReset()
	for _, item := range apps {
		appfilter.UnsafeAdd(item)
	}
}
