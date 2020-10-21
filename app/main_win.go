// +build windows,!wintun

package app

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/device/windivert"
	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
)

func (app *App) Run() (err error) {
	muName := windows.StringToUTF16Ptr("SHADOW-MUTEX")

	mutex, err := windows.OpenMutex(windows.MUTEX_ALL_ACCESS, false, muName)
	if err == nil {
		windows.CloseHandle(mutex)
		return fmt.Errorf("shadow is already running")
	}
	mutex, err = windows.CreateMutex(nil, false, muName)
	if err != nil {
		return fmt.Errorf("create mutex error: %w", err)
	}
	app.attachCloser(mutexHandle(mutex))
	defer func() {
		if err != nil {
			for _, closer := range app.closers {
				closer.Close()
			}
		}
	}()

	event, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("wait for mutex error: %w", err)
	}
	switch event {
	case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
	default:
		return fmt.Errorf("wait for mutex event id error: %w", event)
	}

	resolver, err := common.NewResolver(app.conf.NameServer)
	if err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     resolver.DialContext,
	}

	handler, err := protocol.NewHandler(app.conf.Server, app.timeout)
	if err != nil {
		return fmt.Errorf("protocol error: %w", err)
	}
	app.attachCloser(handler)

	dev, err := windivert.NewDevice(app.conf.FilterString)
	if err != nil {
		return fmt.Errorf("windivert error: %w", err)
	}
	app.attachCloser(dev)
	if err := app.loadAppRules(dev.GetAppFilter()); err != nil {
		return err
	}
	if err := app.loadIPCIDRRules(dev.GetIPFilter()); err != nil {
		return err
	}

	stack := netstack.NewStack(handler, dev, resolver, app.logger)
	app.loadDomainRules(stack.GetDomainTree())
	app.attachCloser(stack)

	if addr := app.conf.ProxyServer; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		app.server.Logger = app.logger
		app.server.handler = handler
		app.server.tree = stack.GetDomainTree()
		go app.server.Serve(ln)
	}

	return nil
}

func (app *App) loadIPCIDRRules(filter *common.IPFilter) error {
	filter.Lock()
	filter.UnsafeReset()
	for _, item := range app.conf.IPCIDRRules.Proxy {
		filter.UnsafeAdd(item)
	}
	filter.Unlock()

	if len(app.conf.GeoIP.Proxy) == 0 && len(app.conf.GeoIP.Bypass) == 0 {
		return nil
	}
	return filter.SetGeoIP(app.conf.GeoIP.File, app.conf.GeoIP.Proxy, app.conf.GeoIP.Bypass, strings.ToLower(app.conf.GeoIP.Final) == "proxy")
}

type PidError struct {
	v string
}

func (e PidError) Error() string {
	return fmt.Sprintf("Pid strconv error: %v", e.v)
}

func (app *App) loadAppRules(filter *common.AppFilter) error {
	filter.Lock()
	filter.UnsafeReset()
	for _, item := range app.conf.AppRules.Proxy {
		filter.UnsafeAdd(item)
	}
	filter.Unlock()

	if env := os.Getenv("SHADOW_PIDS"); env != "" {
		ss := strings.Split(env, ",")
		pids := make([]uint32, 0, len(ss))
		for _, v := range ss {
			i, err := strconv.Atoi(v)
			if err != nil {
				if v != "" {
					return PidError{v}
				}
			}
			pids = append(pids, uint32(i))
		}
		filter.SetPIDs(pids)
	}
	return nil
}

type mutexHandle windows.Handle

func (mu mutexHandle) Close() error {
	windows.ReleaseMutex(windows.Handle(mu))
	windows.CloseHandle(windows.Handle(mu))
	return nil
}
