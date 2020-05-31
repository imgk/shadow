// +build windows

package app

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows"

	"github.com/imgk/shadow/device/windivert"
	"github.com/imgk/shadow/dns"
	"github.com/imgk/shadow/log"
	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
	"github.com/imgk/shadow/systray"
	"github.com/imgk/shadow/utils"
)

var Mutex = windows.StringToUTF16Ptr("SHADOW-MUTEX")

func Exit(sigCh chan os.Signal) {
	sigCh <- windows.SIGTERM
}

func CloseMutex(mutex windows.Handle) {
	windows.ReleaseMutex(mutex)
	windows.CloseHandle(mutex)
}

func Run() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, windows.SIGINT, windows.SIGTERM)

	mutex, err := windows.OpenMutex(windows.MUTEX_ALL_ACCESS, false, Mutex)
	if err == nil {
		windows.CloseHandle(mutex)
		log.Logf("shadow is already running")
		return
	}
	mutex, err = windows.CreateMutex(nil, false, Mutex)
	if err != nil {
		log.Logf("create mutex error: %v", err)
		return
	}
	defer CloseMutex(mutex)

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

	if err := LoadConfig(file); err != nil {
		log.Logf("load config config.json error: %v", err)
		return
	}
	LoadDomainRules(dns.MatchTree())

	if err := dns.SetResolver(conf.NameServer); err != nil {
		log.Logf("dns server error")
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
				log.Logf("plugin error: %v", err)
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

	dev, err := windivert.NewDevice(conf.FilterString)
	if err != nil {
		log.Logf("windivert error: %v", err)
		return
	}
	defer dev.Close()
	LoadAppRules(dev.AppFilter)
	LoadIPRules(dev.IPFilter)

	stack := netstack.NewStack(handler, dev)
	defer stack.Close()

	go func() {
		if _, err := dev.WriteTo(stack); err != nil {
			log.Logf("netstack exit error: %v", err)
			Exit(sigCh)
			return
		}
	}()

	tray, err := systray.New()
	if err != nil {
		log.Logf("systray error: %v", err)
		return
	}
	defer tray.Stop()

	tray.AppendMenu("Reload Rules", func() {
		if err := LoadConfig(file); err != nil {
			log.Logf("reload config file error: %v", err)
			Exit(sigCh)
			return
		}
		LoadDomainRules(dns.MatchTree())
		LoadAppRules(dev.AppFilter)
		LoadIPRules(dev.IPFilter)
	})
	tray.AppendMenu("Close", func() { Exit(sigCh) })
	if err := tray.Show(10, "Shadowsocks"); err != nil {
		log.Logf("set icon error: %v", err)
		return
	}

	go func() {
		if err := tray.Run(); err != nil {
			log.Logf("tray run error: %v", err)
			Exit(sigCh)
			return
		}
	}()

	log.Logf("shadowsocks is running...")
	<-sigCh
	log.Logf("shadowsocks is closing...")
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

func LoadAppRules(appfilter *utils.AppFilter) {
	appfilter.Lock()
	defer appfilter.Unlock()

	appfilter.UnsafeReset()
	appfilter.UnsafeSetMode(conf.AppRules.Mode)

	for _, v := range conf.AppRules.Programs {
		appfilter.UnsafeAdd(v)
	}
}
