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
	defer func() {
		if err != nil {
			for _, closer := range app.closers {
				closer.Close()
			}
		}
	}()

	name := "utun"
	if tunName := app.conf.TunName; tunName != "" {
		name = tunName
	}
	dev, err := tun.NewDevice(name)
	if err != nil {
		return fmt.Errorf("tun device from name error: %w", err)
	}
	app.attachCloser(dev)
	for _, address := range app.conf.TunAddr {
		err := dev.SetInterfaceAddress(address)
		if err != nil {
			return err
		}
	}
	if err := dev.Activate(); err != nil {
		return fmt.Errorf("turn up tun device error: %w", err)
	}

	stack := netstack.NewStack(handler, dev, resolver, app.writer)
	app.loadDomainRules(stack.DomainTree())
	app.attachCloser(stack)

	if err := dev.AddRouteEntry(app.conf.IPCIDRRules.Proxy); err != nil {
		return fmt.Errorf("add route entry error: %w", err)
	}

	return nil
}
