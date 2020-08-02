// +build linux darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/getlantern/systray"
	"github.com/imgk/shadow/app"
)

func main() {
	file := flag.String("c", "", "config file")
	flag.Parse()

	addr := os.Getenv("Remote")
	if addr == "" {
		runCmd()
		return
	}

	if *file == "" {
		dir, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}
		*file = filepath.Join(dir, ".config", "shadow", "config.json")
	}

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
	go Run(opt)

	fmt.Println("shadow - a transparent proxy for Windows, Linux and macOS")
	fmt.Println("shadow is running...")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	conn.Close()

	systray.Run(func() { onStart(opt.Reload) }, onExit)

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

func runCmd() {
	type conf struct {
		Config string
	}

	env := conf{}
	dir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	b, err := ioutil.ReadFile(filepath.Join(dir, ".config", "shadow", "env.json"))
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(b, &env); err != nil {
		panic(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()

	cmd := exec.Command(os.Args[0], "-c", env.Config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "Remote="+l.Addr().String())
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	sign := make(chan error)
	go accept(l, sign)
	go wait(cmd, sign)
	if err := <-sign; err != nil {
		panic(err)
	}

	return
}

func accept(l net.Listener, sign chan error) {
	conn, err := l.Accept()
	if conn != nil && err == nil {
		conn.Close()
	}
	sign <- err
}

func wait(cmd *exec.Cmd, sign chan error) {
	err := cmd.Wait()
	sign <- err
}

func onStart(reload chan struct{}) {
	systray.SetIcon(icon)
	systray.SetTitle("")
	systray.SetTooltip("Shadow")

	mChange := systray.AddMenuItem("Update Rules", "Update Rules Only")
	mQuit := systray.AddMenuItem("Exit", "Quit Shadow")
	go handle(mChange, mQuit, reload)
}

func handle(mChange, mQuit *systray.MenuItem, reload chan struct{}) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill)
	for {
		select {
		case <-mChange.ClickedCh:
			reload <- struct{}{}
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		case <-sigCh:
			systray.Quit()
			return
		}
	}
}

func onExit() {
	fmt.Println("shadow is closing...")
}

type writer struct{}

func (w writer) Write(b []byte) (int, error) { return len(b), nil }
func (w writer) Sync() error                 { return nil }
