// Shadow: A Transparent Proxy for Windows, Linux and macOS

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/imgk/shadow/app"

	// register protocol
	_ "github.com/imgk/shadow/proto/register"
)

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
	}

	conf := FlagConfig{}
	flag.BoolVar(&conf.Verbose, "v", false, "enable verbose mode")
	flag.StringVar(&conf.FilePath, "c", "config.json", "config file")
	flag.DurationVar(&conf.Timeout, "t", time.Minute*3, "timeout")
	flag.Parse()

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
