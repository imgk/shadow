// +build linux darwin

package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/imgk/shadow/device/tun"
	"github.com/imgk/shadow/log"
	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
)

func Run(mode bool, ctx context.Context, re chan struct{}) error {
	return RunWithFd(mode, ctx, re, 0)
}

func RunWithFd(mode bool, ctx context.Context, re chan struct{}, fd uint) error {
	log.SetMode(mode)

	plugin, err := LoadPlugin(conf.Plugin, conf.PluginOpts)
	if conf.Plugin != "" && err != nil {
		return fmt.Errorf("plugin %v error: %w", conf.Plugin, err)
	}

	if plugin != nil {
		if plugin.Start(); err != nil {
			return fmt.Errorf("plugin start error: %v", err)
		}
		defer plugin.Stop()
		log.Logf("plugin %v start", conf.Plugin)

		go func() {
			if err := plugin.Wait(); err != nil {
				log.Logf("plugin error %v", err)
				return
			}
			log.Logf("plugin %v stop", conf.Plugin)
		}()
	}

	handler, err := protocol.NewHandler(conf.Server, time.Minute)
	if err != nil {
		return fmt.Errorf("shadowsocks error %w", err)
	}

	name := "utun"
	if tunName := os.Getenv("TunName"); tunName != "" {
		name = tunName
	}
	dev := (*tun.Device)(nil)
	if fd == 0 {
		device, err := tun.NewDevice(name)
		if err != nil {
			return fmt.Errorf("tun device from name error: %v", err)
		}
		dev = device
	} else {
		device, err := tun.NewDeviceFromFd(fd)
		if err != nil {
			return fmt.Errorf("tun device from fd error: %v", err)
		}
		dev = device
	}
	defer dev.Close()
	if cidr := os.Getenv("TunAddr"); cidr != "" {
		addr, mask, gateway, err := GetInterfaceConfig(cidr)
		if err != nil {
			return fmt.Errorf("parse TunAddr error: %v", err)
		}

		if err := dev.Activate(addr, mask, gateway); err != nil {
			return fmt.Errorf("activate tun error: %v", err)
		}

		log.Logf("addr: %v, mask: %v, gateway: %v", addr, mask, gateway)
	}

	stack := netstack.NewStack(handler, dev)
	defer stack.Close()
	if err := stack.SetResolver(conf.NameServer); err != nil {
		return fmt.Errorf("dns server error")
	}
	LoadDomainRules(stack.Tree)
	LoadIPRules(stack.IPFilter)

	go func() {
		if _, err := dev.WriteTo(stack); err != nil {
			log.Logf("netstack exit error: %v", err)
		}
	}()

	if cidr := os.Getenv("TunRoute"); cidr != "" {
		addr := strings.Split(cidr, ";")
		if err := dev.AddRoute(addr); err != nil {
			return fmt.Errorf("add tun route table error: %v", err)
		}

		log.Logf("add target: %v to route table", cidr)
	}

	RELOAD:
	for {
		select {
		case <-ctx.Done():
			break RELOAD
		case <-re:
			LoadDomainRules(stack.Tree)
			LoadIPRules(stack.IPFilter)
		}
	}

	return nil
}

func (p *Plugin) Stop() error {
	if err := p.Cmd.Process.Signal(unix.SIGTERM); err != nil {
		if er := p.Cmd.Process.Kill(); er != nil {
			return fmt.Errorf("signal plugin process error: %v, kill plugin process error: %v", err, er)
		}
		p.closed <- struct{}{}

		return fmt.Errorf("signal plugin process error: %v", err)
	}

	select {
	case <-p.closed:
		return nil
	case <-time.After(time.Second):
		if err := p.Cmd.Process.Kill(); err != nil {
			return fmt.Errorf("kill plugin process error: %v", err)
		}
		p.closed <- struct{}{}
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
