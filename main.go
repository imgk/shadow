package main

import (
	"bytes"
	"flag"
	"fmt"
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

	app, err := app.NewApp(*file, time.Minute)
	if err != nil {
		panic(err)
	}
	if *mode {
		app.SetWriter(os.Stdout)
	}

	if err := app.Run(); err != nil {
		panic(err)
	}

	fmt.Println("shadow - a transparent proxy for Windows, Linux and macOS")
	fmt.Println("shadow is running...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill)
	<-sigCh
	fmt.Println("shadow is closing...")

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
