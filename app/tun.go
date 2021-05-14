// +build linux darwin windows,!divert

package app

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os/exec"
	"strings"

	"github.com/imgk/shadow/pkg/handler/recorder"
	"github.com/imgk/shadow/pkg/netstack"
	"github.com/imgk/shadow/pkg/proxy"
	"github.com/imgk/shadow/pkg/resolver"
	"github.com/imgk/shadow/pkg/tun"
	"github.com/imgk/shadow/proto"
)

// RunWithDevice is ...
func (app *App) RunWithDevice(dev *tun.Device) (err error) {
	config := app.Conf
	// new dns resolver
	resolver, err := resolver.NewMultiResolver(config.NameServer, resolver.Fallback)
	if err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     resolver.DialContext,
	}

	// new connection handler
	handler, err := proto.NewHandler(config.Server, app.Timeout)
	if err != nil {
		return fmt.Errorf("protocol error: %w", err)
	}
	handler = recorder.NewHandler(handler)
	app.attachCloser(handler)
	defer func() {
		if err != nil {
			for _, closer := range app.closers {
				closer.Close()
			}
		}
	}()

	router := http.NewServeMux()
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)
	router.Handle("/admin/conns", handler.(*recorder.Handler))
	router.Handle("/admin/proxy.pac", NewPACForSocks5())

	// new tun device
	name := "utun"
	if tunName := config.Tun.TunName; tunName != "" {
		name = tunName
	}
	createDevice := false
	if dev == nil {
		createDevice = true
		mtu := (2 << 10) - 4 /*MTU for Tun*/
		if config.Tun.MTU < 65536 && config.Tun.MTU > 0 {
			mtu = config.Tun.MTU
		}
		dev, err = tun.NewDeviceWithMTU(name, mtu)
		if err != nil {
			return fmt.Errorf("tun device from name error: %w", err)
		}
	}
	app.attachCloser(dev)
	// set tun address
	for _, address := range config.Tun.TunAddr {
		err := dev.SetInterfaceAddress(address)
		if err != nil {
			return err
		}
	}
	if createDevice {
		if err := dev.Activate(); err != nil {
			return fmt.Errorf("turn up tun device error: %w", err)
		}
	}

	// new fake ip tree
	tree, err := NewDomainTree(config)
	if err != nil {
		return
	}
	// new domain matcher
	matcher, err := NewGeoSiteMatcher(config)
	if err != nil {
		return fmt.Errorf("NewDomainMatcher error: %w", err)
	}
	// new netstack
	stack := netstack.NewStack(handler, resolver, tree, matcher, !config.DomainRules.DisableHijack /* true for hijacking queries */)
	err = stack.Start(dev, app.Logger, dev.MTU)
	if err != nil {
		return
	}
	app.attachCloser(stack)

	// enable socks5/http proxy
	if addr := config.ProxyServer; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		server := proxy.NewServer(ln, app.Logger, handler, tree, router)
		app.attachCloser(server)
		go server.Serve()
	}

	// add route table entry
	if err := dev.AddRouteEntry(config.IPCIDRRules.Proxy); err != nil {
		return fmt.Errorf("add route entry error: %w", err)
	}

	if config.Tun.PostUp != "" {
		ss := strings.Split(config.Tun.PostUp, "; ")
		for _, s := range ss {
			ss := strings.Split(s, " ")
			for i := range ss {
				if ss[i] == "%i" {
					ss[i] = dev.Name
				}
			}
			cmd := exec.Command(ss[0], ss[1:]...)
			if err = cmd.Run(); err != nil {
				return
			}
		}
	}

	if config.Tun.PostDown != "" {
		ss := strings.Split(config.Tun.PostDown, "; ")
		c := &Command{Cmds: make([]*exec.Cmd, 0, len(ss))}
		for _, s := range ss {
			ss := strings.Split(s, " ")
			for i := range ss {
				if ss[i] == "%i" {
					ss[i] = dev.Name
				}
			}
			c.Cmds = append(c.Cmds, exec.Command(ss[0], ss[1:]...))
		}
		app.attachCloser(c)
	}

	return nil
}

// Run is ...
func (app *App) Run() error {
	return app.RunWithDevice(nil)
}

// Command is ...
type Command struct {
	Cmds []*exec.Cmd
}

// Close is ...
func (c *Command) Close() (last error) {
	for _, cmd := range c.Cmds {
		if err := cmd.Run(); err != nil {
			last = err
		}
	}
	return
}

// prepareFilterString is ...
func (c *Conf) prepareFilterString() error {
	return nil
}
