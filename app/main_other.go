// +build !windows

package app

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/imgk/shadow/device/tun"
	"github.com/imgk/shadow/log"
	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
)

func Exit(sigCh chan os.Signal) {
	sigCh <- unix.SIGTERM
}

func Run() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, unix.SIGINT, unix.SIGTERM)

	if err := LoadConfig(file); err != nil {
		log.Logf("load config config.json error: %v", err)
		return
	}

	plugin, err := LoadPlugin(conf.Plugin, conf.PluginOpts)
	if conf.Plugin != "" && err != nil {
		log.Logf("plugin %v error: %v", conf.Plugin, err)
		return
	}

	if plugin != nil {
		if plugin.Start(); err != nil {
			log.Logf("plugin start error: %v", err)
			return
		}
		defer plugin.Stop()
		log.Logf("plugin %v start", conf.Plugin)

		go func() {
			if err := plugin.Wait(); err != nil {
				log.Logf("plugin error %v", err)
				Exit(sigCh)
				return
			}
			log.Logf("plugin %v stop", conf.Plugin)
		}()
	}

	handler, err := protocol.NewHandler(conf.Server, time.Minute)
	if err != nil {
		log.Logf("shadowsocks error %v", err)
		return
	}

	name := "utun"
	if tunName := os.Getenv("TunName"); tunName != "" {
		name = tunName
	}
	dev, err := tun.NewDevice(name)
	if err != nil {
		log.Logf("tun device error: %v", err)
		return
	}
	defer dev.Close()
	if cidr := os.Getenv("TunAddr"); cidr != "" {
		addr, mask, gateway, err := GetInterfaceConfig(cidr)
		if err != nil {
			log.Logf("parse TunAddr error: %v", err)
			return
		}

		if err := dev.Activate(addr, mask, gateway); err != nil {
			log.Logf("activate tun error: %v", err)
			return
		}

		log.Logf("addr: %v, mask: %v, gateway: %v", addr, mask, gateway)
	}

	stack := netstack.NewStack(handler, dev)
	defer stack.Close()
	if err := stack.SetResolver(conf.NameServer); err != nil {
		log.Logf("dns server error")
		return
	}
	LoadDomainRules(stack.Tree)
	LoadIPRules(stack.IPFilter)

	go func() {
		if _, err := dev.WriteTo(stack); err != nil {
			log.Logf("netstack exit error: %v", err)
			Exit(sigCh)
			return
		}
	}()

	if cidr := os.Getenv("TunRoute"); cidr != "" {
		addr := strings.Split(cidr, ";")

		if err := dev.AddRoute(addr); err != nil {
			log.Logf("add tun route table error: %v", err)
			return
		}

		log.Logf("add target: %v to route table", cidr)
	}

	log.Logf("shadowsocks is running...")
	<-sigCh
	log.Logf("shadowsocks is closing...")
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
