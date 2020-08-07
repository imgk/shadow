// +build windows

package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/imgk/shadow/executive/windows/pkg"
)

const (
	ServiceName = "Shadow"
	ServiceDesc = "A Transparent Proxy for Windows, Linux and macOS"
)

func main() {
	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		panic(fmt.Errorf("failed to determine if we are running in an interactive session: %v", err))
	}
	if !isIntSess {
		file := flag.String("c", "config.json", "config file")
		flag.Parse()

		elog, err := eventlog.Open(ServiceName)
		if err != nil {
			panic(err)
		}
		defer elog.Close()

		if err := svc.Run(ServiceName, pkg.Service{Log: elog, File: *file}); err != nil {
			elog.Error(1, fmt.Sprintf("%s service failed: %v", ServiceName, err))
			return
		}

		elog.Info(1, fmt.Sprintf("%s service stopped", ServiceName))
		return
	}

	if len(os.Args) < 2 {
		if err := (&pkg.Monitor{ServiceName: ServiceName, ServiceDesc: ServiceDesc}).Run(); err != nil {
			panic(err)
		}
		return
	}

	switch os.Args[1] {
	case "/install":
		conf := "config.json"
		if len(os.Args) == 3 {
			conf = os.Args[2]
		}
		conf, err := pkg.GetConfig(conf)
		if err != nil {
			panic(err)
		}
		if err := pkg.InstallService(ServiceName, ServiceDesc, []string{"-c", conf}); err != nil {
			panic(err)
		}
		fmt.Println("service installed successfully")
	case "/remove":
		if err := pkg.RemoveService(ServiceName); err != nil {
			panic(err)
		}
		fmt.Println("service removed successfully")
	case "/start":
		if err := pkg.StartService(ServiceName); err != nil {
			panic(err)
		}
		fmt.Println("service started successfully")
	case "/stop":
		if err := pkg.ControlService(ServiceName, svc.Stop, svc.Stopped); err != nil {
			panic(err)
		}
		fmt.Println("service stopped successfully")
	default:
		if err := (&pkg.Monitor{ServiceName: ServiceName, ServiceDesc: ServiceDesc}).Run(); err != nil {
			panic(err)
		}
	}
}
