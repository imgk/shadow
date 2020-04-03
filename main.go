package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
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

func init() {
	mode := flag.Bool("v", false, "enable verbose mode")
	flag.Parse()

	log.SetMode(*mode)
}

func main() {
	_, err := windows.OpenMutex(windows.MUTEX_ALL_ACCESS, false, windows.StringToUTF16Ptr("SHADOWSOCKS-WINDIVERT"))
	if err == nil {
		panic(fmt.Errorf("shadowsocks-windivert is already running"))
	}
	mutex, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("SHADOWSOCKS-WINDIVERT"))
	if err != nil {
		panic(fmt.Errorf("create mutex error: %v", err))
	}
	event, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
	if err != nil {
		panic(fmt.Errorf("wait for mutex error: %v", err))
	}
	switch event {
	case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
	default:
		panic(fmt.Errorf("wait for mutex event id error: %v", event))
	}

	if err := loadConfig("config.json", dns.MatchTree()); err != nil {
		panic(fmt.Errorf("load config config.json error: %v", err))
	}

	plugin, err := loadPlugin(conf.Plugin, conf.PluginOpts)
	if conf.Plugin != "" && err != nil {
		panic(fmt.Errorf("plugin %v error: %v", conf.Plugin, err))
	}

	if plugin != nil {
		go func() {
			log.Logf("plugin %v start", conf.Plugin)
			if err := plugin.Run(); err != nil {
				panic(fmt.Errorf("plugin error %v", err))
			}
			log.Logf("plugin %v stop", conf.Plugin)
		}()
	}

	var handler netstack.Handler
	handler, err = shadowsocks.NewHandler(conf.Server, time.Minute)
	if err != nil {
		panic(fmt.Errorf("shadowsocks error %v", err))
	}

	var dev netstack.Device
	dev, err = windivert.NewDevice("and outbound and ip and packet[16] = 44 and packet[17] = 44")
	if err != nil {
		panic(fmt.Errorf("windivert error: %v", err))
	}

	stack := netstack.NewStack(handler, dev)

	go func() {
		if _, err := dev.WriteTo(stack); err != nil {
			panic(fmt.Errorf("netstack exit error: %v", err))
		}
	}()

	go func() {
		if err := dns.Serve(conf.NameServer); err != nil {
			panic(fmt.Errorf("dns exit error: %v", err))
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, windows.SIGINT, windows.SIGTERM)

	tray, err := systray.New()
	if err != nil {
		panic(fmt.Errorf("systray error: %v", err))
	}
	tray.AppendMenu("Reload Rules", func() {
		if err := loadConfig("config.json", dns.MatchTree()); err != nil {
			panic(fmt.Errorf("reload config file error: %v", err))
		}
	})
	tray.AppendMenu("Close", func() {
		sigCh <- windows.SIGTERM
	})
	if err := tray.Show(10, "Shadowsocks"); err != nil {
		panic(fmt.Errorf("set icon error: %v", err))
	}

	go func() {
		if err := tray.Run(); err != nil {
			panic(fmt.Errorf("tray run error: %v", err))
		}
	}()

	log.Logf("shadowsocks is running...")
	<-sigCh

	dev.Close()
	stack.Close()
	dns.Stop()

	if plugin != nil {
		plugin.Stop()
	}

	tray.Stop()
	windows.ReleaseMutex(mutex)
}

var conf struct {
	Server     string
	NameServer string
	Plugin     string
	PluginOpts string
	Proxy      []string
	Direct     []string
	Blocked    []string
}

func loadConfig(f string, matchTree *utils.Tree) error {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, &conf)
	if err != nil {
		return err
	}

	matchTree.Lock()
	defer matchTree.Unlock()

	matchTree.UnsafeReset()

	for _, v := range conf.Proxy {
		matchTree.UnsafeStore(v, "PROXY")
	}

	for _, v := range conf.Direct {
		matchTree.UnsafeStore(v, "DIRECT")
	}

	for _, v := range conf.Blocked {
		matchTree.UnsafeStore(v, "BLOCKED")
	}

	return nil
}

func loadPlugin(name, opts string) (*Plugin, error) {
	log.SetPluginPrefix(name)

	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return nil, errors.New("not a file")
	}

	if !filepath.IsAbs(name) {
		dir, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		name = filepath.Join(dir, name)
	}

	return NewPlugin(name, append([]string{name}, strings.Split(opts, " ")...), log.Writer()), nil
}

type Plugin struct {
	exec.Cmd
	closed chan struct{}
}

func NewPlugin(name string, args []string, w io.Writer) *Plugin {
	return &Plugin{
		Cmd: exec.Cmd{
			Path:   name,
			Args:   args,
			Stdout: w,
			Stderr: w,
		},
		closed: make(chan struct{}, 1),
	}
}

func (p *Plugin) Run() error {
	if err := p.Cmd.Run(); err != nil {
		select {
		case <-p.closed:
			return nil
		case <-time.After(time.Second * 5):
			return fmt.Errorf("plugin ends unexpectedly error: %v", err)
		}
	}

	p.closed <- struct{}{}
	return nil
}

func (p *Plugin) Stop() error {
	if err := p.Cmd.Process.Signal(windows.SIGTERM); err != nil {
		//return fmt.Errorf("signal plugin process error: %v", err) // windows is not supported
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
