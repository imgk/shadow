package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows"

	"github.com/imgk/shadowsocks-windivert/dns"
	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/netstack"
	"github.com/imgk/shadowsocks-windivert/shadowsocks"
	"github.com/imgk/shadowsocks-windivert/systray"
	"github.com/imgk/shadowsocks-windivert/windivert"
)

func main() {
	flag.BoolVar(log.Verbose(), "v", false, "enable verbose mode")
	flag.Parse()

	addrUrl, err := loadConfig("config.json")
	if err != nil {
		panic(fmt.Errorf("load config config.json error: %v", err))
	}

	handler, err := shadowsocks.NewHandler(addrUrl, time.Minute*5)
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
		if err := dns.Serve(); err != nil {
			panic(fmt.Errorf("dns exit error: %v", err))
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, windows.SIGINT, windows.SIGTERM)

	tray, err := systray.New()
	if err != nil {
		panic(fmt.Errorf("systray error: %v", err))
	}
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
	tray.Stop()
}

func loadConfig(f string) (string, error) {
	var cfg struct {
		Server   string
		Proxy    []string
		Direct   []string
		Blocked  []string
	}

	b, err := ioutil.ReadFile(f)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(b, &cfg)
	if err != nil {
		return "", err
	}

	matchTree := dns.MatchTree()

	for _, v := range cfg.Proxy {
		matchTree.Store(v, "PROXY")
	}

	for _, v := range cfg.Direct {
		matchTree.Store(v, "DIRECT")
	}

	for _, v := range cfg.Blocked {
		matchTree.Store(v, "BLOCKED")
	}

	return cfg.Server, nil
}
