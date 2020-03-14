package main

import (
	"flag"
	"fmt"
	"log"
	"io"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows"

	"github.com/imgk/shadowsocks-windivert/netstack"
	"github.com/imgk/shadowsocks-windivert/shadowsocks"
	"github.com/imgk/shadowsocks-windivert/systray"
	"github.com/imgk/shadowsocks-windivert/utils"
	"github.com/imgk/shadowsocks-windivert/windivert"
)

var (
	verbose = false
	matchTree = utils.NewTree(".")
	logger = log.New(os.Stderr, "", log.Lshortfile|log.LstdFlags)
)

func logf(f string, v ...interface{}) {
	if verbose {
		logger.Output(2, fmt.Sprintf(f, v...))
	}
}

func main() {
	flag.BoolVar(&verbose, "v", false, "enable verbose mode")
	flag.Parse()

	addrUrl, err := loadConfig("config.json")
	if err != nil {
		panic(fmt.Errorf("load config config.json error: %v", err))
	}

	handler, err := shadowsocks.NewHandler(addrUrl, time.Minute*5, IPToDomainAddr, logf)
	if err != nil {
		panic(fmt.Errorf("shadowsocks error %v", err))
	}

	dev, err := windivert.NewDevice("and ip and packet[16] = 44 and packet[17] = 44")
	if err != nil {
		panic(fmt.Errorf("windivert error: %v", err))
	}
	defer dev.Close()

	stack := netstack.NewStack(handler, dev.(io.Writer))
	defer stack.Close()

	go func() {
		if wt, ok := dev.(io.WriterTo); ok {
			if _, err := wt.WriteTo(stack.(io.Writer)); err != nil {
				panic(fmt.Errorf("netstack exit error: %v", err))
			}
			return
		}

		if _, err := io.CopyBuffer(stack, dev, make([]byte, 1500)); err != nil {
			panic(fmt.Errorf("netstack exit error: %v", err))
		}
	}()

	go func() {
		if err := Serve(); err != nil {
			panic(fmt.Errorf("dns exit error: %v", err))
		}
	}()

	logf("shadowsocks is running ...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, windows.SIGINT, windows.SIGTERM)

	go func() {
		const iconResID = 10

		tray, err := systray.New()
		if err != nil {
			panic(fmt.Errorf("systray error: %v", err))
		}

		if err := tray.Show(iconResID, "Shadowsocks"); err != nil {
			panic(fmt.Errorf("set icon error: %v", err))
		}

		tray.AppendMenu("Close", func() { sigCh <- windows.SIGTERM })

		if err := tray.Run(); err != nil {
			panic(fmt.Errorf("tray run error: %v", err))
		}
	}()

	<-sigCh
}
