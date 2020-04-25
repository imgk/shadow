// +build !windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"

	"github.com/imgk/shadowsocks-windivert/dns"
	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/netstack"
	"github.com/imgk/shadowsocks-windivert/tun"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, unix.SIGINT, unix.SIGTERM)

	Exit := func(sigCh chan os.Signal) {
		sigCh <- unix.SIGTERM
	}

	if err := loadConfig(file); err != nil {
		log.Logf("load config config.json error: %v", err)

		return
	}
	loadDomainRules(dns.MatchTree())

	plugin, err := loadPlugin(conf.Plugin, conf.PluginOpts)
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

	handler, err := NewHandler(conf.Server, time.Minute)
	if err != nil {
		log.Logf("shadowsocks error %v", err)

		return
	}

	dev, err := tun.NewDevice("utun")
	if err != nil {
		log.Logf("tun device error: %v", err)

		return
	}
	defer dev.Close()
	log.Logf("using tun mode, tun device name: %v", dev.Name)

	stack := netstack.NewStack(handler, dev)
	defer stack.Close()
	loadIPRules(stack.IPFilter)

	go func() {
		if _, err := dev.WriteTo(stack); err != nil {
			log.Logf("netstack exit error: %v", err)
			Exit(sigCh)

			return
		}
	}()

	go func() {
		if err := dns.Serve(conf.NameServer); err != nil {
			log.Logf("dns exit error: %v", err)
			Exit(sigCh)

			return
		}
	}()

	log.Logf("shadowsocks is running...")
	<-sigCh
	log.Logf("shadowsocks is closing...")

	dns.Stop()
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
