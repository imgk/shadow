// +build windows,!wintun

package app

import (
	"context"
	"fmt"
	"time"

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

func Run(mode bool, ctx context.Context, reload chan struct{}, done chan struct{}) error {
	mutex, err := windows.OpenMutex(windows.MUTEX_ALL_ACCESS, false, windows.StringToUTF16Ptr("SHADOW-MUTEX"))
	if err == nil {
		windows.CloseHandle(mutex)
		return fmt.Errorf("shadow is already running")
	}
	mutex, err = windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("SHADOW-MUTEX"))
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

	resolver, err := utils.NewResolver(conf.NameServer)
	if err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}
	SetDefaultResolver(resolver)

	handler, err := protocol.NewHandler(conf.Server, time.Minute)
	if err != nil {
		return fmt.Errorf("shadowsocks error %w", err)
	}

	dev, err := windivert.NewDevice(conf.FilterString)
	if err != nil {
		return fmt.Errorf("windivert error: %w", err)
	}

	stack := netstack.NewStack(handler, dev, resolver, mode)
	defer func() {
		stack.Close()
		close(done)
	}()

RELOAD:
	for {
		LoadAppRules(dev.AppFilter)
		LoadIPCIDRRules(dev.IPFilter)
		LoadDomainRules(stack.DomainTree)

		select {
		case <-ctx.Done():
			break RELOAD
		case <-reload:
			continue
		}
	}

	return nil
}

func LoadIPCIDRRules(ipfilter *utils.IPFilter) {
	ipfilter.Lock()
	defer ipfilter.Unlock()

	ipfilter.UnsafeReset()

	for _, ip := range conf.IPRules.Proxy {
		if err := ipfilter.UnsafeAdd(ip); err != nil {
			fmt.Printf("add ip rule %v error: %v\n", ip, err)
		}
	}
}

func LoadAppRules(appfilter *utils.AppFilter) {
	appfilter.Lock()
	defer appfilter.Unlock()

	appfilter.UnsafeReset()

	for _, v := range conf.AppRules.Proxy {
		appfilter.UnsafeAdd(v)
	}
}
