// +build linux darwin windows,wintun

package app

import (
	"fmt"
	"net"

	"github.com/imgk/shadow/device/tun"
	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
	"github.com/imgk/shadow/utils"
)

func Run(opt Option) error {
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

	name := "utun"
	if tunName := opt.Conf.TunName; tunName != "" {
		name = tunName
	}
	dev, err := tun.NewDevice(name)
	if err != nil {
		return fmt.Errorf("tun device from name error: %w", err)
	}
	for _, address := range opt.Conf.TunAddr {
		err := dev.SetInterfaceAddress(address)
		if err != nil {
			return err
		}
	}
	if err := dev.Activate(); err != nil {
		return fmt.Errorf("turn up tun device error: %w", err)
	}

	stack := netstack.NewStack(handler, dev, resolver, opt.Writer)

	if err := dev.AddRouteEntry(opt.Conf.IPCIDRRules.Proxy); err != nil {
		return fmt.Errorf("add route entry error: %w", err)
	}

RELOAD:
	for {
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
