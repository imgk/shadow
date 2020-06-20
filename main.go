package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

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

	if err := app.SetConfig(b); err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func(mode bool, ctx context.Context) {
		if err := app.Run(mode, ctx, make(chan struct{})); err != nil {
			panic(err)
		}
	}(*mode, ctx)

	fmt.Println("shadow - a transparent proxy for Windows, macOS and Linux")
	fmt.Println("shadow is running...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill)
	<-sigCh
	fmt.Println("shadow is closing...")

	cancel()
}
