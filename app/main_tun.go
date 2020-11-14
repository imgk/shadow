// +build linux darwin windows,wintun

package app

import (
	"fmt"
	"net"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/device/tun"
	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
)

func (app *App) Run() (err error) {
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
	app.attachCloser(handler)
	defer func() {
		if err != nil {
			for _, closer := range app.closers {
				closer.Close()
			}
		}
	}()

	// new tun device
	name := "utun"
	if tunName := app.Conf.TunName; tunName != "" {
		name = tunName
	}
	dev, err := tun.NewDevice(name)
	if err != nil {
		return fmt.Errorf("tun device from name error: %w", err)
	}
	app.attachCloser(dev)
	// set tun address
	for _, address := range app.Conf.TunAddr {
		err := dev.SetInterfaceAddress(address)
		if err != nil {
			return err
		}
	}
	if err := dev.Activate(); err != nil {
		return fmt.Errorf("turn up tun device error: %w", err)
	}

	// new fake ip tree
	tree, err := app.newDomainTree()
	if err != nil {
		return
	}
	// new netstack
	stack := netstack.NewStack(handler, resolver, tree, true)
	app.attachCloser(stack)
	err = stack.Start(dev, app.Logger)
	if err != nil {
		return
	}

	// enable socks5/http proxy
	if addr := app.Conf.ProxyServer; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		server := newProxyServer(ln, app.Logger, handler, tree)
		app.attachCloser(server)
		go server.Serve()
	}

	// add route table entry
	if err := dev.AddRouteEntry(app.Conf.IPCIDRRules.Proxy); err != nil {
		return fmt.Errorf("add route entry error: %w", err)
	}

	return nil
}

func RunWithDevice(device *tun.Device) (err error) {
	return nil
}
