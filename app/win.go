//go:build windows && divert
// +build windows,divert

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
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
	"github.com/imgk/shadow/proto"
)

// Run is ...
func (app *App) Run() error {
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
	app.attachCloser(WindowsMutex(mutex))
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
		return fmt.Errorf("wait for mutex event id error: %v", event)
	}

	// new dns resolver
	resolver, err := resolver.NewMultiResolver(app.Conf.NameServer, resolver.Fallback)
	if err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     resolver.DialContext,
	}

	// new connection handler
	handler, err := proto.NewHandler(app.Conf.Server, app.Timeout)
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
		return fmt.Errorf("NewAppFilter error: %w", err)
	}
	// new ip filter
	ipFilter, err := NewIPFilter(app.Conf)
	if err != nil {
		return fmt.Errorf("NewIPFilter error: %w", err)
	}
	ipFilter.IgnorePrivate()
	defer func() {
		if err != nil {
			ipFilter.Close()
		}
	}()
	// new windivert device
	dev, err := divert.NewDevice(app.Conf.FilterString, appFilter, ipFilter, !app.Conf.DomainRules.DisableHijack /* true for hijacking queries */)
	if err != nil {
		return fmt.Errorf("windivert error: %w", err)
	}
	app.attachCloser(dev)

	// new fake ip tree
	tree, err := NewDomainTree(app.Conf)
	if err != nil {
		return fmt.Errorf("NewDomainTree error: %w", err)
	}
	// new geosite matcher
	matcher, err := NewGeoSiteMatcher(app.Conf)
	if err != nil {
		return fmt.Errorf("NewDomainMatcher error: %w", err)
	}
	// new netstack
	stack := netstack.NewStack(handler, resolver, tree, matcher, !app.Conf.DomainRules.DisableHijack /* true for hijacking queries */)
	err = stack.Start(dev, app.Logger, 1500 /*MTU for WinDivert*/)
	if err != nil {
		return fmt.Errorf("start netstack error: %w", err)
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
		ids := make([]uint32, 0, len(ss))
		for _, v := range ss {
			i, err := strconv.Atoi(v)
			if err != nil && v != "" {
				return nil, fmt.Errorf("strconv (%v) err: %w", v, err)
			}
			ids = append(ids, uint32(i))
		}
		filter.SetPIDs(ids)
	}
	return filter, nil
}

// WindowsMutex is ...
type WindowsMutex windows.Handle

// Close is ...
func (h WindowsMutex) Close() error {
	windows.ReleaseMutex(windows.Handle(h))
	windows.CloseHandle(windows.Handle(h))
	return nil
}

// prepareFilterString is ...
// generate filter string for WinDivert
// ignore packets to dns server and proxy server
func (c *Conf) prepareFilterString() error {
	const Filter44 = "outbound and (ipv6 or (ip and ip.DstAddr != %s and ip.DstAddr != %s))"
	const Filter64 = "outbound and ((ipv6 and ipv6.DstAddr != %s) or (ip and ip.DstAddr != %s))"
	const Filter66 = "outbound and ((ipv6 and ipv6.DstAddr != %s and ipv6.DstAddr != %s) or ip)"

	// ResovleIP is to resovle ip from url
	ResolveIP := func(s string) (net.IP, error) {
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		addr, err := net.ResolveTCPAddr("tcp", u.Host)
		if err != nil {
			return nil, err
		}
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return ipv4, nil
		}
		return addr.IP.To16(), nil
	}

	type Proto struct {
		Proto  string `json:"protocol"`
		URL    string `json:"url,omitempty"`
		Server string `json:"server,omitempty"`
	}
	proto := Proto{}
	if err := json.Unmarshal(c.Server, &proto); err != nil {
		return fmt.Errorf("unmarshal server error: %w", err)
	}
	if proto.URL == "" && proto.Server == "" {
		return errors.New("no server address for parsing")
	}
	server := proto.URL
	if server == "" {
		server = fmt.Sprintf("http://%s", proto.Server)
	}

	proxyIP, err := ResolveIP(server)
	if err != nil {
		return err
	}

	if len(c.NameServer) != 1 {
		return errors.New("only support one name server for WinDivert")
	}
	dnsIP, err := ResolveIP(c.NameServer[0])
	if err != nil {
		return err
	}

	if len(proxyIP) == net.IPv4len && len(dnsIP) == net.IPv4len {
		c.FilterString = fmt.Sprintf(Filter44, proxyIP, dnsIP)
		return nil
	}
	if len(proxyIP) == net.IPv4len && len(dnsIP) == net.IPv6len {
		c.FilterString = fmt.Sprintf(Filter64, dnsIP, proxyIP)
		return nil
	}
	if len(proxyIP) == net.IPv6len && len(dnsIP) == net.IPv4len {
		c.FilterString = fmt.Sprintf(Filter64, proxyIP, dnsIP)
		return nil
	}
	c.FilterString = fmt.Sprintf(Filter66, proxyIP, dnsIP)
	return nil
}
