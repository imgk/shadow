// +build linux darwin windows,wintun

package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/imgk/shadow/device/tun"
	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
	"github.com/imgk/shadow/utils"
)

func Run(mode bool, ctx context.Context, reload chan struct{}, done chan struct{}) error {
	resolver, err := utils.NewResolver(conf.NameServer)
	if err != nil {
		return fmt.Errorf("dns server error: %w", err)
	}
	SetDefaultResolver(resolver)

	handler, err := protocol.NewHandler(conf.Server, time.Minute)
	if err != nil {
		return fmt.Errorf("shadowsocks error %w", err)
	}

	name := "utun"
	if tunName := os.Getenv("TunName"); tunName != "" {
		name = tunName
	}
	dev, err := tun.NewDevice(name)
	if err != nil {
		return fmt.Errorf("tun device from name error: %v", err)
	}
	if cidr := os.Getenv("TunAddr"); cidr != "" {
		addr, mask, gateway, err := GetInterfaceConfig(cidr)
		if err != nil {
			return fmt.Errorf("parse TunAddr error: %v", err)
		}

		if err := dev.Activate(addr, mask, gateway); err != nil {
			return fmt.Errorf("activate tun error: %v", err)
		}

		fmt.Printf("config addr: %v\n", addr)
		fmt.Printf("config mask: %v\n", mask)
		fmt.Printf("config gateway: %v\n", gateway)
	}

	stack := netstack.NewStack(handler, dev, resolver, mode)
	defer func() {
		stack.Close()
		close(done)
	}()

	if cidr := os.Getenv("TunRoute"); cidr != "" {
		addr := strings.Split(cidr, ";")
		if err := dev.AddRouteEntry(addr); err != nil {
			return fmt.Errorf("add tun route table error: %v", err)
		}

		for _, entry := range addr {
			fmt.Printf("add target: %v\n", entry)
		}
	}

RELOAD:
	for {
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

func GetInterfaceConfig(cidr string) (addr, mask, gateway string, err error) {
	ip, ipNet, er := net.ParseCIDR(cidr)
	if er != nil {
		err = er
		return
	}

	ip = ip.To4()
	if ip == nil {
		err = fmt.Errorf("not ipv4 address")
		return
	}

	addr = ip.String()
	mask = net.IP(ipNet.Mask).String()
	ip = ipNet.IP
	ip[3] += 1
	gateway = ip.String()

	return
}
