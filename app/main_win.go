// +build windows,shadow_divert

package app

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
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

	// new dns resolver
	resolver, err := common.NewResolver(app.Conf.NameServer)
	if err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     resolver.DialContext,
	}

	// new connection handler
	handler, err := protocol.NewHandler(app.Conf.Server, app.timeout)
	if err != nil {
		return fmt.Errorf("protocol error: %w", err)
	}
	handler = NewHandler(handler)
	app.attachCloser(handler)

	router := http.NewServeMux()
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)
	router.Handle("/admin/conns", http.Handler(handler.(*Handler)))
	router.HandleFunc("/admin/proxy.pac", ServePAC)

	// new application filter
	appFilter, err := app.newAppFilter()
	if err != nil {
		return
	}
	// new ip filter
	ipFilter, err := app.newIPFilter()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			ipFilter.Close()
		}
	}()
	// new windivert device
	dev, err := windivert.NewDevice(app.Conf.FilterString, appFilter, ipFilter, true)
	if err != nil {
		return fmt.Errorf("windivert error: %w", err)
	}
	app.attachCloser(dev)

	// new fake ip tree
	tree, err := app.newDomainTree()
	if err != nil {
		return
	}
	// new netstack
	stack := netstack.NewStack(handler, resolver, tree, true)
	err = stack.Start(dev, app.Logger)
	if err != nil {
		return
	}
	app.attachCloser(stack)

	// new socks5/http proxy
	if addr := app.Conf.ProxyServer; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		server := newProxyServer(ln, app.Logger, handler, tree, router)
		app.attachCloser(server)
		go server.Serve()
	}

	return nil
}

func (app *App) newIPFilter() (*common.IPFilter, error) {
	filter := common.NewIPFilter()

	filter.Lock()
	for _, item := range app.Conf.IPCIDRRules.Proxy {
		filter.UnsafeAdd(item)
	}
	filter.Unlock()

	if len(app.Conf.GeoIP.Proxy) == 0 && len(app.Conf.GeoIP.Bypass) == 0 {
		return filter, nil
	}
	err := filter.SetGeoIP(app.Conf.GeoIP.File, app.Conf.GeoIP.Proxy, app.Conf.GeoIP.Bypass, app.Conf.GeoIP.Final == "proxy")
	return filter, err
}

type pidError string

func (e pidError) Error() string {
	return fmt.Sprintf("Pid strconv error: %v", string(e))
}

func (app *App) newAppFilter() (*common.AppFilter, error) {
	env := os.Getenv("SHADOW_PIDS")
	if env == "" && len(app.Conf.AppRules.Proxy) == 0 {
		return nil, nil
	}

	filter := common.NewAppFilter()

	filter.Lock()
	for _, item := range app.Conf.AppRules.Proxy {
		filter.UnsafeAdd(item)
	}
	filter.Unlock()

	if env != "" {
		ss := strings.Split(env, ",")
		pids := make([]uint32, 0, len(ss))
		for _, v := range ss {
			i, err := strconv.Atoi(v)
			if err != nil {
				if v != "" {
					return nil, pidError(v)
				}
			}
			pids = append(pids, uint32(i))
		}
		filter.SetPIDs(pids)
	}
	return filter, nil
}

type mutexHandle windows.Handle

func (mu mutexHandle) Close() error {
	windows.ReleaseMutex(windows.Handle(mu))
	windows.CloseHandle(windows.Handle(mu))
	return nil
}
