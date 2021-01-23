// Shadow: A Transparent Proxy for Windows, Linux and macOS

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/imgk/shadow/app"
)

func main() {
	var conf struct {
		Verbose  bool
		FilePath string
		Timeout  time.Duration
	}
	flag.BoolVar(&conf.Verbose, "v", false, "enable verbose mode")
	flag.StringVar(&conf.FilePath, "c", "config.json", "config file")
	flag.DurationVar(&conf.Timeout, "t", time.Minute, "timeout")
	flag.Parse()

	// if not verbose, discard all logs
	w := io.Writer(ioutil.Discard)
	if conf.Verbose {
		w = os.Stdout
	}
	app, err := app.NewApp(conf.FilePath, conf.Timeout, w)
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
