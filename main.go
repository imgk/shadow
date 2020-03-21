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

func main() {
	flag.BoolVar(log.Verbose(), "v", false, "enable verbose mode")
	flag.Parse()

	mutex, err := windows.CreateMutex(nil, true, windows.StringToUTF16Ptr("SHADOWSOCKS-WINDIVERT"))
	if err != nil {
		panic(fmt.Errorf("create mutex error: %v", err))
	}

	if err := loadConfig("config.json", dns.MatchTree()); err != nil {
		panic(fmt.Errorf("load config config.json error: %v", err))
	}

	pluginCmd, err := loadPlugin(conf.Plugin, conf.PluginOpts)
	if conf.Plugin != "" && err != nil {
		panic(fmt.Errorf("plugin error: %v", err))
	}

	pluginCh := make(chan struct{})
	if pluginCmd != nil {
		go func() {
			log.Logf("plugin %v start", conf.Plugin)
			if err := pluginCmd.Run(); err != nil {
				select {
				case <-pluginCh:
				case <-time.After(time.Second * 5):
					panic(fmt.Errorf("plugin error %v", err))
				}
			}
			pluginCh <- struct{}{}
			log.Logf("plugin %v stop", conf.Plugin)
		}()
	}

	handler, err := shadowsocks.NewHandler(conf.Server, time.Minute)
	if err != nil {
		panic(fmt.Errorf("shadowsocks error %v", err))
	}

	dev, err := windivert.NewDevice("and ip and packet[16] = 44 and packet[17] = 44")
	if err != nil {
		panic(fmt.Errorf("windivert error: %v", err))
	}

	stack := netstack.NewStack(handler, dev.(io.Writer))

	go func() {
		if wt, ok := dev.(io.WriterTo); ok {
			if _, err := wt.WriteTo(stack.(io.Writer)); err != nil {
				panic(fmt.Errorf("netstack exit error: %v", err))
			}
			return
		}

		if _, err := io.CopyBuffer(stack, dev, make([]byte, 2048)); err != nil {
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
	tray.AppendMenu("Close", func() { sigCh <- windows.SIGTERM })
	if err := tray.Show(10, "Shadowsocks"); err != nil {
		panic(fmt.Errorf("set icon error: %v", err))
	}

	go func() {
		if err := tray.Run(); err != nil {
			panic(fmt.Errorf("tray run error: %v", err))
		}
	}()

	log.Logf("shadowsocks is running ...")
	<-sigCh

	dev.Close()
	stack.Close()

	if pluginCmd != nil {
		if err := pluginCmd.Process.Signal(windows.SIGTERM); err != nil {
			//log.Logf("signal plugin process error: %v", err) // windows not supported
		}

		select {
		case <-pluginCh:
		case <-time.After(time.Second):
			if err := pluginCmd.Process.Kill(); err != nil {
				log.Logf("kill plugin process error: %v", err)
			}
			pluginCh <- struct{}{}
		}
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

	for _, v := range conf.Proxy {
		matchTree.Store(v, "PROXY")
	}

	for _, v := range conf.Direct {
		matchTree.Store(v, "DIRECT")
	}

	for _, v := range conf.Blocked {
		matchTree.Store(v, "BLOCKED")
	}

	return nil
}

func loadPlugin(name, opts string) (*exec.Cmd, error) {
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

	w := log.Writer("Plugin:")
	cmd := &exec.Cmd{
		Path:   name,
		Args:   append([]string{name}, strings.Split(opts, " ")...),
		Stdout: w,
		Stderr: w,
	}

	return cmd, nil
}
