// +build windows,shadow_divert

package app

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/imgk/shadow/pkg/divert"
	"github.com/imgk/shadow/pkg/divert/filter"
	"github.com/imgk/shadow/pkg/handler/recorder"
	"github.com/imgk/shadow/pkg/netstack"
	"github.com/imgk/shadow/pkg/proxy"
	"github.com/imgk/shadow/pkg/resolver"
	"github.com/imgk/shadow/protocol"
)

// Run is ...
func (app *App) Run() (err error) {
	muName := windows.StringToUTF16Ptr("SHADOW-MUTEX")
	// prevent openning more that one instance
	mutex, err := windows.OpenMutex(windows.MUTEX_ALL_ACCESS, false, muName)
	if err == nil {
		windows.CloseHandle(mutex)
		return errors.New("shadow is already running")
	}
	mutex, err = windows.CreateMutex(nil, false, muName)
	if err != nil {
		return fmt.Errorf("create mutex error: %w", err)
	}
	app.attachCloser(&Mutex{Handle: mutex})
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
	resolver, err := resolver.NewResolver(app.Conf.NameServer)
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
	handler = recorder.NewHandler(handler)
	app.attachCloser(handler)

	router := http.NewServeMux()
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)
	router.Handle("/admin/conns", handler.(*recorder.Handler))
	router.Handle("/admin/proxy.pac", NewPACForSocks5())

	// new application filter
	appFilter, err := NewAppFilter(app.Conf)
	if err != nil {
		return
	}
	// new ip filter
	ipFilter, err := NewIPFilter(app.Conf)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			ipFilter.Close()
		}
	}()
	// new windivert device
	dev, err := divert.NewDevice(app.Conf.FilterString, appFilter, ipFilter, true)
	if err != nil {
		return fmt.Errorf("windivert error: %w", err)
	}
	app.attachCloser(dev)

	// new fake ip tree
	tree, err := NewDomainTree(app.Conf)
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

		server := proxy.NewServer(ln, app.Logger, handler, tree, router)
		app.attachCloser(server)
		go server.Serve()
	}

	return nil
}

// NewIPFilter is ...
func NewIPFilter(conf *Conf) (*filter.IPFilter, error) {
	filter := filter.NewIPFilter()

	filter.Lock()
	for _, item := range conf.IPCIDRRules.Proxy {
		filter.UnsafeAdd(item)
	}
	filter.Unlock()

	if len(conf.GeoIP.Proxy) == 0 && len(conf.GeoIP.Bypass) == 0 {
		return filter, nil
	}
	err := filter.SetGeoIP(conf.GeoIP.File, conf.GeoIP.Proxy, conf.GeoIP.Bypass, conf.GeoIP.Final == "proxy")
	return filter, err
}

// NewAppFilter is ...
func NewAppFilter(conf *Conf) (*filter.AppFilter, error) {
	env := os.Getenv("SHADOW_PIDS")
	if env == "" && len(conf.AppRules.Proxy) == 0 {
		return nil, nil
	}

	filter := filter.NewAppFilter()

	filter.Lock()
	for _, item := range conf.AppRules.Proxy {
		filter.UnsafeAdd(item)
	}
	filter.Unlock()

	if env != "" {
		ss := strings.Split(env, ",")
		pids := make([]uint32, 0, len(ss))
		for _, v := range ss {
			i, err := strconv.Atoi(v)
			if err != nil && v != "" {
				return nil, fmt.Errorf("strconv (%v) err: %w", v, err)
			}
			pids = append(pids, uint32(i))
		}
		filter.SetPIDs(pids)
	}
	return filter, nil
}

// Mutex is ...
type Mutex struct {
	Handle windows.Handle
}

// Close is ...
func (m *Mutex) Close() error {
	windows.ReleaseMutex(m.Handle)
	windows.CloseHandle(m.Handle)
	return nil
}
