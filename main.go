package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/imgk/shadow/app"
)

func main() {
	mode := flag.Bool("v", false, "enable verbose mode")
	file := flag.String("c", "config.json", "config file")
	flag.Parse()

	b, err := ioutil.ReadFile(*file)
	if err != nil {
		panic(err)
	}

	conf := &app.Conf{}
	if err := conf.Unmarshal(b); err != nil {
		panic(err)
	}
	b = nil

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	opt := app.Option{
		Conf:    conf,
		Writer:  writer{},
		Ctx:     ctx,
		Reload:  make(chan struct{}),
		Done:    done,
		Timeout: time.Minute,
	}
	if *mode {
		opt.Writer = os.Stdout
	}
	go Run(opt)

	fmt.Println("shadow - a transparent proxy for Windows, Linux and macOS")
	fmt.Println("shadow is running...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill)
	<-sigCh
	fmt.Println("shadow is closing...")

	cancel()
	select {
	case <-time.After(time.Second * 10):
		buf := make([]byte, 1024)
		for {
			n := runtime.Stack(buf, true)
			if n < len(buf) {
				buf = buf[:n]
				break
			}
			buf = make([]byte, 2*len(buf))
		}
		lines := bytes.Split(buf, []byte{'\n'})
		fmt.Println("Failed to shutdown after 10 seconds. Probably dead locked. Printing stack and killing.")
		for _, line := range lines {
			if len(bytes.TrimSpace(line)) > 0 {
				fmt.Println(string(line))
			}
		}
		os.Exit(777)
	case <-done:
	}
}

func Run(option app.Option) {
	if err := app.Run(option); err != nil {
		panic(err)
	}
}

type writer struct{}

func (w writer) Write(b []byte) (int, error) { return len(b), nil }
func (w writer) Sync() error                 { return nil }
