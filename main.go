package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/imgk/shadowsocks-windivert/core"
)

func main() {
	core.Run()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
