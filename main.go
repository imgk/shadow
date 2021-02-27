// Shadow: A Transparent Proxy for Windows, Linux and macOS

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/imgk/shadow/app"

	// register protocol
	_ "github.com/imgk/shadow/proto/register"
)

var version = "devel"

func main() {
	type FlagConfig struct {
		// Verbose is ...
		// enable verbose mode
		Verbose bool
		// FilePath is ...
		// path to config file
		FilePath string
		// Timeout is ...
		// UDP timeout duration
		Timeout time.Duration
		// BuildInfo is ...
		// show build info
		BuildInfo bool
	}

	conf := FlagConfig{}
	flag.BoolVar(&conf.Verbose, "v", false, "enable verbose mode")
	flag.StringVar(&conf.FilePath, "c", "config.json", "config file")
	flag.DurationVar(&conf.Timeout, "t", time.Minute*3, "timeout")
	flag.BoolVar(&conf.BuildInfo, "f", false, "build info")
	flag.Parse()

	if conf.BuildInfo {
		fmt.Printf("build version: %v\n", version)
		printBuildInfo()
		return
	}

	w := io.Writer(nil)
	if conf.Verbose {
		w = os.Stdout
	}
	app, err := app.NewApp(conf.FilePath, conf.Timeout, w /* nil for no output*/)
	if err != nil {
		log.Panic(err)
	}

	// start app
	if err := app.Run(); err != nil {
		log.Panic(err)
	}

	fmt.Println("shadow - a transparent proxy for Windows, Linux and macOS")
	fmt.Println("shadow is running...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
	fmt.Println("shadow is closing...")

	// close app
	app.Close()

	// use os.Exit when failed to close app
	// and print runtime.Stack
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
	case <-app.Done():
	}
}

func printBuildInfo() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Panic(errors.New("no build info"))
	}
	printModule(&info.Main)
	for _, m := range info.Deps {
		printModule(m)
	}
}

func printModule(m *debug.Module) {
	if m.Replace == nil {
		fmt.Printf("%s@%s\n", m.Path, m.Version)
		return
	}
	fmt.Printf("%s@%s => %s@%s\n", m.Path, m.Version, m.Replace.Path, m.Replace.Version)
}
