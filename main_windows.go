// +build windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows"

	"github.com/imgk/shadowsocks-windivert/dns"
	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/netstack"
	"github.com/imgk/shadowsocks-windivert/shadowsocks"
	"github.com/imgk/shadowsocks-windivert/systray"
	"github.com/imgk/shadowsocks-windivert/utils"
	"github.com/imgk/shadowsocks-windivert/windivert"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, windows.SIGINT, windows.SIGTERM)

	mutex, err := windows.OpenMutex(windows.MUTEX_ALL_ACCESS, false, windows.StringToUTF16Ptr("SHADOWSOCKS-WINDIVERT"))
	if err == nil {
		windows.CloseHandle(mutex)
		log.Logf("shadowsocks-windivert is already running")

		return
	}
	mutex, err = windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("SHADOWSOCKS-WINDIVERT"))
	if err != nil {
		log.Logf("create mutex error: %v", err)

		return
	}
	event, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
	if err != nil {
		log.Logf("wait for mutex error: %v", err)

		return
	}
	switch event {
	case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
	default:
		log.Logf("wait for mutex event id error: %v", event)

		return
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
				log.Logf("plugin error: %v", err)
				sigCh <- windows.SIGTERM

				return
			}
			log.Logf("plugin %v stop", conf.Plugin)
		}()
	}

	handler, err := shadowsocks.NewHandler(conf.Server, time.Minute)
	if err != nil {
		log.Logf("shadowsocks error %v", err)

		return
	}

	dev, err := windivert.NewDevice("outbound")
	if err != nil {
		log.Logf("windivert error: %v", err)

		return
	}
	defer dev.Close()
	loadAppRules(dev.AppFilter)
	loadIPRules(dev.IPFilter)

	stack := netstack.NewStack(handler, dev)
	defer stack.Close()
	stack.IPFilter.Add("0.0.0.0/1")
	stack.IPFilter.Add("128.0.0.0/1")
	stack.IPFilter.Add("::/1")
	stack.IPFilter.Add("ffff::/1")
	stack.IPFilter.Sort()

	go func() {
		if _, err := dev.WriteTo(stack); err != nil {
			log.Logf("netstack exit error: %v", err)
			sigCh <- windows.SIGTERM

			return
		}
	}()

	go func() {
		if err := dns.Serve(conf.NameServer); err != nil {
			log.Logf("dns exit error: %v", err)
			sigCh <- windows.SIGTERM

			return
		}
	}()

	tray, err := systray.New()
	if err != nil {
		log.Logf("systray error: %v", err)

		return
	}
	tray.AppendMenu("Reload Rules", func() {
		if err := loadConfig("config.json"); err != nil {
			log.Logf("reload config file error: %v", err)
			sigCh <- windows.SIGTERM

			return
		}
		loadDomainRules(dns.MatchTree())
		loadAppRules(dev.AppFilter)
		loadIPRules(dev.IPFilter)
	})
	tray.AppendMenu("Close", func() {
		sigCh <- windows.SIGTERM
	})
	if err := tray.Show(10, "Shadowsocks"); err != nil {
		log.Logf("set icon error: %v", err)

		return
	}

	go func() {
		if err := tray.Run(); err != nil {
			log.Logf("tray run error: %v", err)
			sigCh <- windows.SIGTERM

			return
		}
	}()

	log.Logf("shadowsocks is running...")
	<-sigCh
	log.Logf("shadowsocks is closing...")

	dns.Stop()
	tray.Stop()

	windows.ReleaseMutex(mutex)
	windows.CloseHandle(mutex)
}

func (p *Plugin) Stop() error {
	if err := p.Cmd.Process.Signal(windows.SIGTERM); err != nil {
		// return fmt.Errorf("signal plugin process error: %v", err) // windows is not supported
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

func loadAppRules(appfilter *utils.AppFilter) {
	appfilter.Lock()
	defer appfilter.Unlock()

	appfilter.UnsafeReset()

	for _, v := range conf.Programs {
		appfilter.UnsafeAdd(v)
	}

	conf.Programs = nil
}
